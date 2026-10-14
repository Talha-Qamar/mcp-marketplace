/**
 * MCP Secure — Submissions: the pre-publication gate (spec §9, §10)
 * =================================================================
 * A publisher submits a source (git repo, uploaded files, or a bundled demo
 * server). The listing is created hidden ('pending') and a submission row is
 * queued. The worker scans queued submissions one at a time (the models are
 * CPU-bound) and applies the verdict:
 *
 *   PASS    → approved, listed
 *   REVIEW  → in_review, waits for an admin decision (stored in review_decisions)
 *   FAIL    → rejected
 *   error   → failed (ingestion or scan error; never listed)
 *   a newer submission of the same server → older queued/in-review ones are 'superseded'
 *
 * The submission row is the job: rows left mid-scan by a crash are re-queued
 * on start. Progress events are kept in memory per submission so the UI can
 * attach (SSE) at any point and replay what it missed.
 */

const { EventEmitter } = require('events');
const { v4: uuidv4 } = require('uuid');
const { oneRow, allRows, runSql, getServerBySlug, createServer } = require('../db');
const service = require('./service');
const store = require('./store');
const listing = require('./listing');
const { waitForRequiredAnalyzers } = require('./orchestrator/local_services');

const STATE_FOR_VERDICT = { PASS: 'approved', REVIEW: 'in_review', FAIL: 'rejected' };
const DEMO_SOURCES = new Set(['weather-tools', 'db-helper', 'shell-runner']);
const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,62}$/;

const bus = new EventEmitter();
bus.setMaxListeners(100);
const history = new Map(); // submissionId -> events[] (bounded, in memory)
let working = false;

function now() {
  return new Date().toISOString();
}

function emit(id, event, data) {
  const list = history.get(id) || [];
  list.push({ event, data });
  if (list.length > 200) list.shift();
  history.set(id, list);
  bus.emit(id, { event, data });
}

function rowToSubmission(r) {
  if (!r) return null;
  return {
    id: r.id,
    serverId: r.server_id,
    submitterId: r.submitter_id,
    source: JSON.parse(r.source_json),
    declaredTools: r.declared_tools_json ? JSON.parse(r.declared_tools_json) : [],
    state: r.state,
    verdict: r.verdict,
    scanRecordId: r.scan_record_id,
    error: r.error,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

function getSubmission(id) {
  return rowToSubmission(oneRow(`SELECT * FROM submissions WHERE id = ?`, [id]));
}

function setState(id, state, extra = {}) {
  const fields = ['state = ?', 'updated_at = ?'];
  const params = [state, now()];
  for (const [col, val] of Object.entries(extra)) { fields.push(`${col} = ?`); params.push(val); }
  params.push(id);
  runSql(`UPDATE submissions SET ${fields.join(', ')} WHERE id = ?`, params);
  console.log(`[MCS] submission ${id.slice(0, 8)} → ${state}${extra.verdict ? ` (${extra.verdict})` : ''}${extra.error ? `: ${extra.error}` : ''}`);
  emit(id, 'state', { state, ...extra });
}

/**
 * Validate and normalise what a publisher sent as the code source.
 * Local filesystem paths are never accepted from users; `demo` maps a known
 * demo name onto the bundled demo_servers/ directory.
 */
function normaliseSource(input) {
  const src = input || {};
  if (src.kind === 'git') {
    if (!src.repo_url || !/^https:\/\//.test(src.repo_url)) throw badRequest('source.repo_url must be a public https git URL');
    return { kind: 'git', repo_url: String(src.repo_url).trim(), ref: src.ref ? String(src.ref).trim() : undefined };
  }
  if (src.kind === 'files') {
    if (!Array.isArray(src.files) || src.files.length === 0) throw badRequest('source.files must be a non-empty array of {path, content}');
    return { kind: 'files', files: src.files.map(f => ({ path: String(f.path || ''), content: String(f.content || '') })) };
  }
  if (src.kind === 'demo') {
    if (!DEMO_SOURCES.has(src.name)) throw badRequest(`unknown demo server '${src.name}'`);
    return { kind: 'local', path: `demo_servers/${src.name}`, demo: src.name };
  }
  throw badRequest("source.kind must be 'git', 'files' or 'demo'");
}

function badRequest(message) {
  const e = new Error(message);
  e.status = 400;
  return e;
}

function slugify(name) {
  return String(name || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63);
}

/**
 * Create a submission. A new slug creates a hidden listing; an existing slug
 * owned by the same user creates a new version of that listing.
 */
function createSubmission(user, body) {
  const source = normaliseSource(body.source);
  const name = String(body.name || '').trim();
  if (!name) throw badRequest('name is required');
  const slug = body.slug ? String(body.slug).trim() : slugify(name);
  if (!SLUG_RE.test(slug)) throw badRequest('slug must be 2-63 characters of a-z, 0-9 and -');
  const declaredTools = (Array.isArray(body.declared_tools) ? body.declared_tools : [])
    .filter(t => t && t.name)
    .map(t => ({ name: String(t.name), description: String(t.description || '') }));

  let server = getServerBySlug(slug);
  if (server && server.author_id !== user.id) {
    const e = new Error('A server with this slug already exists and belongs to someone else');
    e.status = 409;
    throw e;
  }
  if (!server) {
    const category = (body.category_id && oneRow(`SELECT id FROM categories WHERE id = ? OR slug = ?`, [body.category_id, body.category_id]))
      || oneRow(`SELECT id FROM categories ORDER BY name LIMIT 1`);
    server = createServer({
      slug,
      name,
      author_id: user.id,
      description: String(body.description || ''),
      long_description: String(body.long_description || ''),
      github_url: source.kind === 'git' ? source.repo_url : '',
      language: body.language || 'other',
      hosting: body.hosting || 'local',
      license: body.license || 'MIT',
      version: body.version || '1.0.0',
      category_id: category.id,
      tools: declaredTools,
      source,
      listing_status: 'pending',
    });
  } else {
    runSql(`UPDATE servers SET source_json = ?, updated_at = ? WHERE id = ?`, [JSON.stringify(source), now(), server.id]);
    // A newer version replaces any older one still waiting for a scan or a review.
    const stale = allRows(`SELECT id FROM submissions WHERE server_id = ? AND state IN ('queued', 'in_review')`, [server.id]);
    for (const old of stale) setState(old.id, 'superseded');
  }

  const id = uuidv4();
  const ts = now();
  runSql(`INSERT INTO submissions (id, server_id, submitter_id, source_json, declared_tools_json, state, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, 'queued', ?, ?)`,
    [id, server.id, user.id, JSON.stringify(source), JSON.stringify(declaredTools), ts, ts]);
  emit(id, 'state', { state: 'queued' });
  setImmediate(kick);
  return { submission: getSubmission(id), server: getServerBySlug(slug) };
}

async function processOne(sub) {
  const server = oneRow(`SELECT * FROM servers WHERE id = ?`, [sub.serverId]);
  setState(sub.id, 'ingesting');
  const scans = store.getScanRecords(server.id);
  const version = scans.length > 0 ? scans[0].version + 1 : 1;
  let scanning = false;
  const onStage = async (e) => {
    if (!scanning && e.stage !== 'ingest' && e.status === 'start') {
      scanning = true;
      setState(sub.id, 'scanning');
    }
    emit(sub.id, 'stage', e);
  };
  try {
    const result = await service.runFullPipeline({
      serverId: server.id,
      source: sub.source,
      listing: { name: server.name, description: server.description || '', slug: server.slug, declared_language: server.language },
      declaredTools: sub.declaredTools,
    }, version, false, onStage);
    const verdict = result.scanRecord.verdict;
    if (verdict === 'PASS') for (const prev of scans) if (prev.verdict === 'PASS') store.markScanSuperseded(prev.id);
    const listingStatus = listing.applyVerdict(server, verdict);
    setState(sub.id, STATE_FOR_VERDICT[verdict], {
      verdict,
      scan_record_id: result.attestation.attestationId,
    });
    emit(sub.id, 'result', {
      submissionId: sub.id,
      listingStatus,
      scanRecord: result.scanRecord,
      attestation: result.attestation,
      logIndex: result.logIndex,
      anchored: result.anchored,
      version,
    });
  } catch (e) {
    console.error(`[MCS] submission ${sub.id} failed:`, e.message);
    setState(sub.id, 'failed', { error: e.message });
    emit(sub.id, 'error', { error: e.message, code: e.code });
  }
}

/** Drain the queue, one submission at a time. */
async function kick() {
  if (working) return;
  working = true;
  try {
    for (;;) {
      const next = rowToSubmission(oneRow(`SELECT * FROM submissions WHERE state = 'queued' ORDER BY created_at LIMIT 1`));
      if (!next) break;
      await waitForRequiredAnalyzers();
      await processOne(next);
    }
  } finally {
    working = false;
  }
}

/** Re-queue submissions interrupted by a restart, then start the worker. */
function startWorker() {
  const r = runSql(`UPDATE submissions SET state = 'queued', updated_at = ? WHERE state IN ('ingesting', 'scanning')`, [now()]);
  if (r.changes) console.log(`[MCS] re-queued ${r.changes} interrupted submission(s)`);
  setImmediate(kick);
}

function subscribe(id, listener) {
  for (const e of history.get(id) || []) listener(e);
  bus.on(id, listener);
  return () => bus.off(id, listener);
}

function listForUser(userId) {
  return allRows(`SELECT sb.*, s.slug, s.name FROM submissions sb JOIN servers s ON s.id = sb.server_id
                  WHERE sb.submitter_id = ? ORDER BY sb.created_at DESC LIMIT 100`, [userId])
    .map(r => ({ ...rowToSubmission(r), slug: r.slug, name: r.name }));
}

function reviewQueue() {
  return allRows(`SELECT sb.*, s.slug, s.name, s.description, u.username AS submitter
                  FROM submissions sb JOIN servers s ON s.id = sb.server_id JOIN users u ON u.id = sb.submitter_id
                  WHERE sb.state = 'in_review' ORDER BY sb.updated_at ASC`)
    .map(r => {
      const scan = r.scan_record_id ? store.getScanRecordById(r.scan_record_id) : null;
      return {
        ...rowToSubmission(r),
        slug: r.slug,
        name: r.name,
        description: r.description,
        submitter: r.submitter,
        scan: scan && {
          id: scan.id,
          version: scan.version,
          verdict: scan.verdict,
          policy: scan.policy,
          analyzers: scan.analyzers,
          triage: scan.triage,
          subject: scan.subject,
          createdAt: scan.createdAt,
        },
      };
    });
}

/** An admin's decision on an in_review submission (decision D2: the human decides). */
function decide(id, reviewer, decision, note) {
  if (!['approve', 'reject'].includes(decision)) throw badRequest("decision must be 'approve' or 'reject'");
  if (!note || !String(note).trim()) throw badRequest('a note explaining the decision is required');
  const sub = getSubmission(id);
  if (!sub) { const e = new Error('Submission not found'); e.status = 404; throw e; }
  if (sub.state !== 'in_review') { const e = new Error(`Submission is '${sub.state}', not in review`); e.status = 409; throw e; }

  const server = oneRow(`SELECT * FROM servers WHERE id = ?`, [sub.serverId]);
  runSql(`INSERT INTO review_decisions (id, submission_id, scan_record_id, reviewer_id, decision, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [uuidv4(), id, sub.scanRecordId, reviewer.id, decision, String(note).trim(), now()]);
  if (decision === 'approve') {
    runSql(`UPDATE servers SET listing_status = 'approved', security_status = 'reviewed', updated_at = ? WHERE id = ?`, [now(), server.id]);
    setState(id, 'approved');
  } else {
    const next = listing.LISTED.has(server.listing_status) ? 'suspended' : 'rejected';
    runSql(`UPDATE servers SET listing_status = ?, updated_at = ? WHERE id = ?`, [next, now(), server.id]);
    setState(id, 'rejected');
  }
  return getSubmission(id);
}

function decisionsFor(id) {
  return allRows(`SELECT d.*, u.username AS reviewer FROM review_decisions d JOIN users u ON u.id = d.reviewer_id
                  WHERE d.submission_id = ? ORDER BY d.created_at`, [id]);
}

module.exports = {
  createSubmission, getSubmission, listForUser, reviewQueue, decide, decisionsFor,
  subscribe, startWorker, kick, normaliseSource,
};
