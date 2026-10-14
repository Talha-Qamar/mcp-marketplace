#!/usr/bin/env node
/**
 * Evaluation runner: scans eval/corpus.json (known-vulnerable releases and
 * their fixed twins) and eval/benign.json with the PRODUCTION pipeline, and
 * writes one JSON line per scan to eval/results/<name>.jsonl (resumable).
 *
 *   node eval/run_eval.js [--set vuln|benign|all] [--limit N] [--only <id-substring>] [--out name]
 *
 * For a vulnerable case with a fixed twin, the lines changed by the fix
 * (GitHub compare API) are recorded so the report can check whether a finding
 * points at the code the security fix touched (localization).
 */

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { runPipeline } = require('../src/mcpsecure/orchestrator/pipeline');
const { ensureLocalAnalyzers, stopLocalAnalyzers } = require('../src/mcpsecure/orchestrator/local_services');
const { resolveCommit, parseRepoUrl } = require('../src/mcpsecure/ingest/sources');

const HERE = __dirname;
const arg = (name, def) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : def; };
const SET = arg('set', 'all');
const LIMIT = Number(arg('limit', 0));
const ONLY = arg('only', null);
const OUT = path.join(HERE, 'results', `${arg('out', 'latest')}.jsonl`);

function sourceFor(c, ref) {
  const url = c.subdir ? `${c.repo}/tree/${ref}/${c.subdir}` : c.repo;
  return { kind: 'git', repo_url: url, ref };
}

/** Old-side line ranges changed by the fix, per file path relative to the scanned root. */
function changedLines(c) {
  const m = c.repo.match(/github\.com\/([^/]+\/[^/]+)/);
  try {
    const out = execFileSync('gh', ['api', `repos/${m[1]}/compare/${c.vulnerable.commit}...${c.fixed.commit}`, '-q',
      '[.files[] | {filename, patch}]'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 120000 });
    const files = {};
    for (const f of JSON.parse(out || '[]')) {
      if (!f.patch) continue;
      let rel = f.filename;
      if (c.subdir) {
        if (!rel.startsWith(c.subdir + '/')) continue;
        rel = rel.slice(c.subdir.length + 1);
      }
      const ranges = [];
      let oldLine = 0;
      for (const line of f.patch.split('\n')) {
        const h = line.match(/^@@ -(\d+)(?:,(\d+))? \+/);
        if (h) { oldLine = Number(h[1]); continue; }
        if (line.startsWith('-')) { ranges.push(oldLine); oldLine++; }
        else if (line.startsWith('+')) { ranges.push(Math.max(oldLine - 1, 1)); } // insertion point
        else oldLine++;
      }
      if (ranges.length) files[rel] = [...new Set(ranges)].sort((a, b) => a - b);
    }
    return files;
  } catch (e) {
    return { __error: e.message.slice(0, 200) };
  }
}

function summarize(out) {
  return {
    verdict: out.policy.verdict,
    reasons: out.policy.reasons.map(r => ({ rule: r.rule, verdict: r.verdict, message: r.message })),
    commit: out.bundle.source.commit_sha,
    fingerprint: out.bundle.content_fingerprint,
    files: out.bundle.files.length,
    languages: [...new Set(out.bundle.files.map(f => f.language))],
    tools: out.bundle.tools.length,
    tool_discovery: out.bundle.coverage.tool_discovery,
    slots: out.slots.map(s => ({
      slot: s.slot, status: s.result.status, engine: s.result.analyzer.engine, error: s.result.error || null,
      units: s.result.coverage, findings: (s.result.findings || []).map(f => ({
        id: f.finding_id, threat: f.threat, score: f.score, severity: f.severity,
        file: f.location.file, line: f.location.line, fn: f.location.function, tool: f.location.tool_id, summary: f.summary,
      })),
    })),
    effective: out.policy.effective_findings,
  };
}

async function scan(source) {
  const t0 = Date.now();
  try {
    const out = await runPipeline({ source, listing: { name: source.repo_url.split('/').slice(-1)[0] } });
    return { ok: true, seconds: (Date.now() - t0) / 1000, ...summarize(out) };
  } catch (e) {
    return { ok: false, seconds: (Date.now() - t0) / 1000, error: e.message };
  }
}

(async () => {
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  const done = new Set(fs.existsSync(OUT) ? fs.readFileSync(OUT, 'utf8').split('\n').filter(Boolean).map(l => { const j = JSON.parse(l); return `${j.set}:${j.id}:${j.version}`; }) : []);
  const write = rec => fs.appendFileSync(OUT, JSON.stringify(rec) + '\n');

  await ensureLocalAnalyzers({ log: m => console.error(m) });
  const jobs = [];
  if (SET === 'vuln' || SET === 'all') {
    for (const c of require('./corpus.json').cases) {
      jobs.push({ set: 'vuln', c, version: 'vulnerable' });
      if (c.fixed) jobs.push({ set: 'vuln', c, version: 'fixed' });
    }
  }
  if (SET === 'benign' || SET === 'all') {
    const benign = JSON.parse(fs.readFileSync(path.join(HERE, 'benign.json'), 'utf8'));
    let pinned = false;
    for (const c of benign.cases) {
      if (!c.commit) {
        try { c.commit = await resolveCommit(parseRepoUrl(c.repo).cloneUrl, 'HEAD'); pinned = true; } catch (e) { c.commit = null; }
      }
      jobs.push({ set: 'benign', c, version: 'head' });
    }
    if (pinned) fs.writeFileSync(path.join(HERE, 'benign.json'), JSON.stringify(benign, null, 2) + '\n');
  }

  let n = 0;
  for (const job of jobs) {
    const key = `${job.set}:${job.c.id}:${job.version}`;
    if (done.has(key)) continue;
    if (ONLY && !job.c.id.includes(ONLY)) continue;
    if (LIMIT && n >= LIMIT) break;
    n++;
    const commit = job.version === 'vulnerable' ? job.c.vulnerable.commit : job.version === 'fixed' ? job.c.fixed.commit : job.c.commit;
    const res = await scan(sourceFor(job.c, commit));
    const rec = { set: job.set, id: job.c.id, version: job.version, repo: job.c.repo, subdir: job.c.subdir || null,
      expected_threats: job.c.threats || [], by_design: job.c.by_design || null, ...res };
    if (job.set === 'vuln' && job.version === 'vulnerable' && job.c.fixed) rec.fix_changed_lines = changedLines(job.c);
    write(rec);
    console.error(`[${n}] ${key.padEnd(70)} ${res.ok ? res.verdict : 'ERROR ' + res.error.slice(0, 80)} (${res.seconds.toFixed(1)}s)`);
  }
  stopLocalAnalyzers();
})().catch(e => { console.error(e); stopLocalAnalyzers(); process.exit(1); });
