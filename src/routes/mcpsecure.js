/**
 * MCP Secure — API Routes
 * ========================
 * Mounted at /api/mcs
 *
 * All routes return JSON. Crypto operations run server-side;
 * the public key is exposed so clients can verify signatures independently.
 */

const express = require('express');
const router = express.Router();

const service = require('../mcpsecure/service');
const store = require('../mcpsecure/store');
const listing = require('../mcpsecure/listing');
const { normaliseSource, pollWatched, DEMO_MODE } = require('../mcpsecure/submissions');
const { requireAdmin } = require('../middleware/auth');

const TESTBED_REPO = process.env.MCS_TESTBED_REPO || 'https://github.com/Talha-Qamar/mcp-secure-testbed';

/**
 * Per-IP limit for the open scan endpoints (scan-preview, verify-external):
 * each request clones and scans a repository. MCS_SCAN_RATE_LIMIT per hour.
 */
// Demo mode allows more: one presenter scans many testbed cases from one machine.
const SCAN_LIMIT = Number(process.env.MCS_SCAN_RATE_LIMIT || (DEMO_MODE ? 300 : 30));
const scanHits = new Map();
function scanRateLimit(req, res, next) {
  const key = req.ip;
  const hour = Date.now() - 3600000;
  const hits = (scanHits.get(key) || []).filter(t => t > hour);
  if (hits.length >= SCAN_LIMIT) return res.status(429).json({ error: `rate limit: at most ${SCAN_LIMIT} scans per hour` });
  hits.push(Date.now());
  scanHits.set(key, hits);
  next();
}

/** Demo-only routes answer 404 when DEMO_MODE is off. */
function demoOnly(req, res, next) {
  if (!DEMO_MODE) return res.status(404).json({ error: 'demo features are disabled (DEMO_MODE is off)' });
  next();
}
const { ingest } = require('../mcpsecure/ingest');
const { REPO_ROOT } = require('../mcpsecure/ingest/sources');
const { getServerBySlug, oneRow } = require('../db');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const os = require('os');
const path = require('path');

// ─── Client config (demo mode, testbed) ───────────────────────────────────────
router.get('/config', (req, res) => {
  res.json({ demoMode: DEMO_MODE, testbedRepo: TESTBED_REPO });
});

// ─── Public key endpoint (needed by client-side verify) ────────────────────────
router.get('/pubkey', (req, res) => {
  try {
    res.json(service.getPublicKeyExport());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Scan helpers (shared by POST /scan and GET /scan/stream) ─────────────────

/** A candidate reference from a form: `demo:<name>` (bundled demo server) or a git URL. */
function sourceFromRef(ref, gitRef) {
  const m = /^demo:([a-z-]+)$/.exec(String(ref || '').trim());
  return m ? normaliseSource({ kind: 'demo', name: m[1] }) : normaliseSource({ kind: 'git', repo_url: ref, ref: gitRef });
}

/** Where a listing's code comes from: stored source, else a real GitHub URL. */
function serverSource(server) {
  if (server.source_json) {
    try { return JSON.parse(server.source_json); } catch (_) { /* fall through */ }
  }
  if (server.github_url && /^https:\/\/github\.com\/[^/]+\/[^/]+/.test(server.github_url)) {
    return { kind: 'git', repo_url: server.github_url };
  }
  return null;
}

// The rug-pull demo: demo_servers/_bait/<slug>/ files replace the originals,
// which is exactly what a malicious new commit does. Demo servers only.
function baitOverlay(slug) {
  const rel = `demo_servers/_bait/${slug}`;
  return fs.existsSync(path.join(REPO_ROOT, rel)) ? rel : null;
}

function scanRequestFor(server, source) {
  return {
    serverId: server.id,
    source,
    listing: { name: server.name, description: server.description || '', slug: server.slug, declared_language: server.language || null },
    declaredTools: (server.tools || []).map(t => ({ name: t.name, description: t.description || '' })),
  };
}

function buildScanJob(serverSlug, baitAndSwitch) {
  const server = getServerBySlug(serverSlug);
  if (!server) return { error: 'Server not found', status: 404 };

  let source = serverSource(server);
  if (!source) {
    return { error: 'This listing has no scannable source: no git repository or uploaded code is on record.', status: 422 };
  }
  if (baitAndSwitch) {
    const overlay = source.kind === 'local' && baitOverlay(server.slug);
    if (!overlay) return { error: 'Bait-and-switch is a demo for the bundled demo servers only.', status: 400 };
    source = { ...source, overlay };
  }

  const existingScans = store.getScanRecords(server.id);
  const version = existingScans.length > 0 ? existingScans[0].version + 1 : 1;
  return { server, version, existingScans, request: scanRequestFor(server, source), onStage: null };
}

async function executeScan(job) {
  if (job.version > 1) {
    for (const prev of job.existingScans) {
      if (prev.verdict === 'PASS') store.markScanSuperseded(prev.id);
    }
  }

  const result = await service.runFullPipeline(job.request, job.version, false, job.onStage);
  const listingStatus = listing.applyVerdict(job.server, result.scanRecord.verdict);

  return {
    scanRecord: result.scanRecord,
    attestation: result.attestation,
    logIndex: result.logIndex,
    anchored: result.anchored,
    version: job.version,
    listingStatus,
  };
}

/** Ingestion failures are the candidate's problem (422), not the server's (500). */
function scanErrorStatus(e) {
  return e && (e.code === 'INGEST_FAILED' || e.code === 'BAD_SOURCE') ? 422 : 500;
}

// ─── Run a scan on a known marketplace server ─────────────────────────────────
router.post('/scan', async (req, res) => {
  try {
    const { serverSlug, baitAndSwitch } = req.body;
    if (!serverSlug) return res.status(400).json({ error: 'serverSlug is required' });

    const job = buildScanJob(serverSlug, baitAndSwitch);
    if (job.error) return res.status(job.status).json({ error: job.error });

    res.json(await executeScan(job));
  } catch (e) {
    console.error('[MCS /scan]', e.message);
    res.status(scanErrorStatus(e)).json({ error: e.message, code: e.code });
  }
});

// ─── The same scan, streamed ──────────────────────────────────────────────────
// Server-Sent Events. Each stage is emitted when it ACTUALLY completes, with
// its real duration, so the UI reflects the backend instead of replaying a
// fixed 750ms-per-step script. EventSource only speaks GET, hence query params.
router.get('/scan/stream', async (req, res) => {
  const { serverSlug } = req.query;
  const baitAndSwitch = req.query.baitAndSwitch === 'true' || req.query.baitAndSwitch === '1';

  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  if (typeof res.flushHeaders === 'function') res.flushHeaders();

  let closed = false;
  req.on('close', () => { closed = true; });

  const send = async (event, data) => {
    if (closed) return;
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    // Yield to the event loop so these bytes actually leave the socket before
    // the next stage starts. Without this the pipeline is synchronous enough
    // that every event would arrive in one burst at the end.
    await new Promise(resolve => setImmediate(resolve));
  };

  try {
    if (!serverSlug) {
      await send('error', { error: 'serverSlug is required' });
      return res.end();
    }

    const job = buildScanJob(serverSlug, baitAndSwitch);
    if (job.error) {
      await send('error', { error: job.error });
      return res.end();
    }

    await send('begin', {
      serverSlug,
      version: job.version,
      baitAndSwitch,
      toolCount: job.request.declaredTools.length,
    });

    job.onStage = async (event) => { await send('stage', event); };

    const result = await executeScan(job);
    await send('result', result);
  } catch (e) {
    console.error('[MCS /scan/stream]', e.message);
    try { await send('error', { error: e.message, code: e.code }); } catch (_) { /* socket gone */ }
  } finally {
    res.end();
  }
});

// ─── Get all scan records (with optional serverId filter) ─────────────────────
router.get('/scans', (req, res) => {
  try {
    const { serverId, serverSlug } = req.query;
    if (serverSlug) {
      const server = getServerBySlug(serverSlug);
      if (!server) return res.status(404).json({ error: 'Server not found' });
      return res.json(store.getScanRecords(server.id));
    }
    if (serverId) return res.json(store.getScanRecords(serverId));
    res.json(store.getAllScanRecords());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Get single scan/attestation record ──────────────────────────────────────
router.get('/attestations/:id', (req, res) => {
  try {
    const record = store.getScanRecordById(req.params.id);
    if (!record) return res.status(404).json({ error: 'Attestation not found' });
    res.json(record);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Transparency log ─────────────────────────────────────────────────────────
router.get('/log', (req, res) => {
  try {
    const leaves = store.getLogLeaves();
    const sth = service.getSignedTreeHead();
    res.json({ leaves, signedTreeHead: sth });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/log/:index/proof', (req, res) => {
  try {
    const leafIndex = parseInt(req.params.index, 10);
    const proof = service.getInclusionProof(leafIndex);
    res.json(proof);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ─── Anchor receipts ──────────────────────────────────────────────────────────
router.get('/anchors', (req, res) => {
  try {
    res.json(store.getAnchors());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/anchors/trigger', (req, res) => {
  try {
    const receipt = service.simulateAnchor();
    if (!receipt) return res.status(400).json({ error: 'No log entries to anchor' });
    res.json(receipt);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Watcher dashboard ────────────────────────────────────────────────────────
router.get('/watcher', (req, res) => {
  try {
    const rows = store.getWatcherRows();
    // Enrich with server info
    const enriched = rows.map(row => {
      const server = oneRow(`
        SELECT s.id, s.slug, s.name, s.version FROM servers s WHERE s.id = ?
      `, [row.serverId]);
      return { ...row, server: server || null };
    });
    res.json(enriched);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Simulate update (docs-only or bait-and-switch) ───────────────────────────
// Both updates are real re-ingestions of the demo server with an overlay
// applied, so the watcher logic is exercised for real: a docs-only change
// leaves the content fingerprint (which covers code, tools and listing text,
// not the README) unchanged and needs no re-scan; a code swap changes it and
// triggers one.
// ─── Poll watched repositories (real watcher) ─────────────────────────────────
// git ls-remote on each listed git server's watched ref; a new commit is
// re-scanned through the submission gate. Anyone may trigger it in demo mode,
// admins otherwise.
router.post('/watcher/poll', (req, res, next) => (DEMO_MODE ? next() : requireAdmin(req, res, next)), async (req, res) => {
  try {
    res.json({ polled: await pollWatched() });
  } catch (e) {
    console.error('[MCS /watcher/poll]', e.message);
    res.status(500).json({ error: e.message });
  }
});

router.post('/watcher/:serverId/simulate-update', demoOnly, async (req, res) => {
  let tmp = null;
  try {
    const { serverId } = req.params;
    const { updateType } = req.body; // 'docs_only' | 'bait_and_switch'

    const row = oneRow(`SELECT slug FROM servers WHERE id = ?`, [serverId]);
    if (!row) return res.status(404).json({ error: 'Server not found' });
    const server = getServerBySlug(row.slug);
    const source = serverSource(server);
    if (!source || source.kind !== 'local') {
      return res.status(400).json({ error: 'Simulated updates are a demo for the bundled demo servers only.' });
    }

    const watcher = store.getWatcherRow(serverId);
    const lastFingerprint = watcher ? watcher.lastFingerprint : null;

    if (updateType === 'docs_only') {
      tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mcs-docs-'));
      const readme = path.join(REPO_ROOT, source.path, 'README.md');
      const original = fs.existsSync(readme) ? fs.readFileSync(readme, 'utf8') : '';
      fs.writeFileSync(path.join(tmp, 'README.md'), `${original}\n\n## Changelog\n- Documentation update (${new Date().toISOString().slice(0, 10)})\n`);

      const bundle = await ingest({ ...scanRequestFor(server, { ...source, overlay: tmp }) });
      const changed = bundle.content_fingerprint !== lastFingerprint;
      if (changed) {
        return res.json({
          updateType: 'docs_only',
          message: 'Unexpected: the content fingerprint changed on a README-only update. Re-scan from the scan page.',
          fingerprintChanged: true, rescanned: false, oldFingerprint: lastFingerprint, newFingerprint: bundle.content_fingerprint,
        });
      }
      store.upsertWatcherRow({
        serverId,
        watchedRef: watcher ? watcher.watchedRef : 'main',
        lastSeenSha: watcher ? watcher.lastSeenSha : null,
        lastFingerprint,
        lastVerdict: watcher ? watcher.lastVerdict : null,
        lastCheckedAt: new Date().toISOString(),
        status: 'up_to_date',
      });
      return res.json({
        updateType: 'docs_only',
        message: 'README changed, code did not: the re-computed content fingerprint is identical, so the verdict carries forward without a re-scan.',
        fingerprintChanged: false,
        rescanned: false,
        fingerprint: bundle.content_fingerprint,
        verdict: watcher ? watcher.lastVerdict : null,
      });
    }

    if (updateType === 'bait_and_switch') {
      const job = buildScanJob(server.slug, true);
      if (job.error) return res.status(job.status).json({ error: job.error });
      const result = await executeScan(job);
      const subject = result.scanRecord.subject;

      store.upsertWatcherRow({
        serverId,
        watchedRef: watcher ? watcher.watchedRef : 'main',
        lastSeenSha: subject.commit_sha,
        lastFingerprint: subject.content_fingerprint,
        lastVerdict: result.scanRecord.verdict,
        lastCheckedAt: new Date().toISOString(),
        status: 'up_to_date',
      });

      return res.json({
        updateType: 'bait_and_switch',
        message: 'Code changed, so the content fingerprint changed — automatic re-scan triggered. Previous PASS is now superseded.',
        newVersion: job.version,
        fingerprintChanged: lastFingerprint !== subject.content_fingerprint,
        oldFingerprint: lastFingerprint,
        newFingerprint: subject.content_fingerprint,
        rescanned: true,
        newVerdict: result.scanRecord.verdict,
        listingStatus: result.listingStatus,
        scanRecord: result.scanRecord,
        attestation: result.attestation,
      });
    }

    res.status(400).json({ error: 'updateType must be "docs_only" or "bait_and_switch"' });
  } catch (e) {
    console.error('[MCS /watcher/simulate-update]', e.message);
    res.status(scanErrorStatus(e)).json({ error: e.message });
  } finally {
    if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ─── External verifier (Feature 4) ───────────────────────────────────────────
// MCP Secure scanning a repository on behalf of an external party. The
// candidate is ingested and scanned like any submission, but NEVER added to
// the marketplace catalog.
router.post('/verify-external', scanRateLimit, async (req, res) => {
  try {
    const { requesterName, candidateRef, ref } = req.body;
    if (!candidateRef) return res.status(400).json({ error: 'candidateRef (a public git repository URL) is required' });

    const name = String(candidateRef).replace(/\/$/, '').split(/[/:]/).pop() || 'external-server';
    const request = {
      serverId: 'external:' + uuidv4(),
      source: sourceFromRef(candidateRef, ref),
      listing: { name, description: `External candidate scanned on behalf of ${requesterName || 'an external requester'}` },
      declaredTools: [],
    };
    const result = await service.runFullPipeline(request, 1, true);

    store.saveExternalRequest({
      requesterName: requesterName || 'Anonymous',
      candidateRef,
      verdict: result.scanRecord.verdict,
      attestationId: result.attestation.attestationId,
    });

    res.json({
      onboarded: false, // Always false — enforced
      requesterName: requesterName || 'Anonymous',
      candidateRef,
      message: `Scanned on behalf of "${requesterName || 'Anonymous'}"; not onboarded here.`,
      scanRecord: result.scanRecord,
      attestation: result.attestation,
      logIndex: result.logIndex,
      anchored: result.anchored,
    });
  } catch (e) {
    console.error('[MCS /verify-external]', e.message);
    res.status(e.status || scanErrorStatus(e)).json({ error: e.message });
  }
});

// ─── Client-side verify by fingerprint ────────────────────────────────────────
router.get('/verify-fingerprint', (req, res) => {
  try {
    const { fingerprint } = req.query;
    if (!fingerprint) return res.status(400).json({ error: 'fingerprint is required' });

    const record = store.getScanRecordByFingerprint(fingerprint);
    if (!record) return res.json({ found: false, fingerprint });

    // Get log proof
    const leaves = store.getLogLeaves();
    const leafIdx = leaves.findIndex(l => l.attestationId === record.attestation.attestationId);
    let proof = null;
    if (leafIdx >= 0) {
      try { proof = service.getInclusionProof(leafIdx); } catch {}
    }

    // Get anchors
    const anchors = store.getAnchors();
    const sth = service.getSignedTreeHead();
    const pk = service.getPublicKeyExport();

    res.json({
      found: true,
      record,
      logIndex: leafIdx,
      proof,
      signedTreeHead: sth,
      anchors,
      publicKey: pk,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── External requests list ───────────────────────────────────────────────────
router.get('/external-requests', (req, res) => {
  try {
    res.json(store.getExternalRequests());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── MCP endpoint inspector mock ──────────────────────────────────────────────
// Returns a simulated MCP tool call JSON in/out for the UI inspector
router.post('/mcp-endpoint-mock', (req, res) => {
  try {
    const { candidateRef, requesterName } = req.body;

    const mcpRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: {
        name: 'verify_mcp_server',
        arguments: {
          candidate_ref: candidateRef || 'https://github.com/example/server',
          requester: requesterName || 'external-marketplace',
          include_evidence: true,
          include_attestation: true,
        },
      },
      id: uuidv4(),
    };

    res.json({ mcpRequest, note: 'SIMULATED MCP ENDPOINT — real production MCP will expose this as a callable tool' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Scan Preview ─────────────────────────────────────────────────────────────
// Scans a public repository without creating a listing (kept for API callers;
// the publish page uses /api/v1/submissions).
router.post('/scan-preview', scanRateLimit, async (req, res) => {
  try {
    const { content } = req.body;
    if (!content || !content.github_url) {
      return res.status(400).json({ error: 'content.github_url (a public git repository) is required' });
    }
    const request = {
      serverId: 'preview:' + uuidv4(),
      source: sourceFromRef(content.github_url, content.ref),
      listing: { name: content.name || 'Unnamed', description: content.description || '' },
      declaredTools: (content.tools || []).map(t => ({ name: t.name || '', description: t.description || t.desc || '' })),
    };
    const result = await service.runFullPipeline(request, 1, true);
    res.json({
      scanRecord: result.scanRecord,
      attestation: result.attestation,
      logIndex: result.logIndex,
      anchored: result.anchored,
      preview: true,
    });
  } catch (e) {
    console.error('[MCS /scan-preview]', e.message);
    res.status(e.status || scanErrorStatus(e)).json({ error: e.message });
  }
});

// ─── Stats ────────────────────────────────────────────────────────────────────
router.get('/stats', (req, res) => {
  try {
    const allScans = store.getAllScanRecords(1000);
    const verdicts = { PASS: 0, REVIEW: 0, FAIL: 0 };
    for (const s of allScans) verdicts[s.verdict] = (verdicts[s.verdict] || 0) + 1;

    res.json({
      totalScans: allScans.length,
      verdicts,
      logLeaves: store.getLogLeaves().length,
      logSize:   store.getLogLeaves().length,
      anchors:   store.getAnchors().length,
      externalRequests: store.getExternalRequests().length,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
