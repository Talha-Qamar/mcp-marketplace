#!/usr/bin/env node
/**
 * MCP Secure — headless scan CLI (spec §13)
 *
 *   node bin/mcs-scan.js <git-url | demo:<name> | ./local-dir> [--ref <branch|tag|sha>] [--json]
 *   node bin/mcs-scan.js --batch list.txt [--json]      one ref per line
 *
 * Runs exactly the production pipeline (ingest → analyzers → policy → triage)
 * with no database and no marketplace, for evaluation, baselines and CI.
 * Exit code: 0 PASS · 1 FAIL · 2 REVIEW · 3 error (batch: the worst result).
 */

const fs = require('fs');
const path = require('path');
const { runPipeline } = require('../src/mcpsecure/orchestrator/pipeline');
const { ensureLocalAnalyzers, stopLocalAnalyzers } = require('../src/mcpsecure/orchestrator/local_services');

const EXIT = { PASS: 0, FAIL: 1, REVIEW: 2, ERROR: 3 };
// For a batch, the exit code is the worst single result.
const SEVERITY = { PASS: 0, REVIEW: 1, FAIL: 2, ERROR: 3 };

function parseArgs(argv) {
  const out = { refs: [], json: false, ref: undefined };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--json') out.json = true;
    else if (argv[i] === '--ref') out.ref = argv[++i];
    else if (argv[i] === '--batch') out.refs.push(...fs.readFileSync(argv[++i], 'utf8').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#')));
    else out.refs.push(argv[i]);
  }
  return out;
}

function sourceFor(ref, gitRef) {
  const demo = /^demo:([a-z-]+)$/.exec(ref);
  if (demo) return { kind: 'local', path: `demo_servers/${demo[1]}` };
  if (/^https:\/\//.test(ref)) return { kind: 'git', repo_url: ref, ref: gitRef };
  return { kind: 'local', path: path.resolve(ref) };
}

async function scanOne(ref, opts) {
  const t0 = Date.now();
  try {
    const out = await runPipeline({ source: sourceFor(ref, opts.ref), listing: { name: ref.split(/[/:]/).pop() } });
    const summary = {
      ref,
      verdict: out.policy.verdict,
      commit_sha: out.bundle.source.commit_sha,
      content_fingerprint: out.bundle.content_fingerprint,
      tools: out.bundle.tools.map(t => t.name),
      reasons: out.policy.reasons,
      analyzers: out.slots.map(s => ({ slot: s.slot, status: s.result.status, engine: s.result.analyzer.engine, findings: (s.result.findings || []).length })),
      findings: out.policy.effective_findings,
      seconds: (Date.now() - t0) / 1000,
    };
    if (!opts.json) {
      console.log(`${summary.verdict.padEnd(6)} ${ref}  (${summary.tools.length} tools, ${summary.seconds.toFixed(1)}s${summary.commit_sha ? `, ${summary.commit_sha.slice(0, 12)}` : ''})`);
      for (const r of summary.reasons) console.log(`         ${r.rule}: ${r.message}`);
    }
    return summary;
  } catch (e) {
    if (!opts.json) console.log(`ERROR  ${ref}  ${e.message}`);
    return { ref, verdict: 'ERROR', error: e.message };
  }
}

(async () => {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.refs.length === 0) {
    console.error('usage: node bin/mcs-scan.js <git-url | demo:<name> | dir> [--ref r] [--json] | --batch file');
    process.exit(3);
  }
  await ensureLocalAnalyzers({ log: m => { if (!opts.json) console.error(m); } });
  const results = [];
  for (const ref of opts.refs) results.push(await scanOne(ref, opts));
  if (opts.json) console.log(JSON.stringify(results.length === 1 ? results[0] : results, null, 2));
  stopLocalAnalyzers();
  const worst = results.reduce((w, r) => (SEVERITY[r.verdict] > SEVERITY[w] ? r.verdict : w), 'PASS');
  process.exit(EXIT[worst]);
})();
