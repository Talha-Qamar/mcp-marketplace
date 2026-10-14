#!/usr/bin/env node
/**
 * Analyzer contract conformance suite (spec §6.5).
 *
 *   node scripts/conformance.js --url http://127.0.0.1:8703
 *
 * An analyzer must pass this before it is added to config/analyzers.json.
 * Golden bundles are produced by ingesting the bundled demo servers, so they
 * are always current with the bundle format. Checks:
 *   1. /v1/health and /v1/analyze responses validate against contracts/*.schema.json
 *   2. analysing the same bundle twice gives byte-identical results
 *   3. findings are sorted as the contract requires and use known threat ids
 *   4. empty and unsupported-language bundles return a contract status, not an HTTP error
 */

const Ajv = require('ajv/dist/2020');
const { ingest } = require('../src/mcpsecure/ingest');
const threats = require('../contracts/threats.json').threats;

const args = process.argv.slice(2);
const url = (args[args.indexOf('--url') + 1] || '').replace(/\/$/, '');
if (!url || args.indexOf('--url') < 0) {
  console.error('usage: node scripts/conformance.js --url <analyzer base url>');
  process.exit(2);
}

const ajv = new Ajv({ allErrors: true, strict: false });
const validHealth = ajv.compile(require('../contracts/analyzer-health.schema.json'));
const validResult = ajv.compile(require('../contracts/analyzer-result.schema.json'));

let failures = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '  ✓' : '  ✗'} ${label}${!ok && detail ? `\n      ${detail}` : ''}`);
  if (!ok) failures++;
};

async function analyze(bundle) {
  const res = await fetch(`${url}/v1/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ bundle, context: {} }),
    signal: AbortSignal.timeout(600000),
  });
  return { status: res.status, body: await res.text() };
}

function sortedLikeContract(findings) {
  const key = f => [(f.location && f.location.file) || '', (f.location && f.location.line) || 0, f.threat, f.finding_id];
  for (let i = 1; i < findings.length; i++) {
    const a = key(findings[i - 1]);
    const b = key(findings[i]);
    for (let j = 0; j < a.length; j++) {
      if (a[j] < b[j]) break;
      if (a[j] > b[j]) return false;
    }
  }
  return true;
}

(async () => {
  console.log(`Conformance: ${url}\n`);
  const health = await fetch(`${url}/v1/health`).then(r => r.json());
  check(validHealth(health), `health: valid (${health.id} ${health.version}, engine ${health.engine})`, ajv.errorsText(validHealth.errors));

  const golden = [];
  for (const name of ['weather-tools', 'db-helper', 'shell-runner']) {
    golden.push([name, await ingest({ source: { kind: 'local', path: `demo_servers/${name}` }, listing: { name } })]);
    golden.push([`${name} (bait)`, await ingest({ source: { kind: 'local', path: `demo_servers/${name}`, overlay: `demo_servers/_bait/${name}` }, listing: { name } })]);
  }
  const empty = { ...golden[0][1], files: [], tools: [], metadata_files: [], coverage: { tool_discovery: 'none', notes: [] } };
  const goOnly = { ...empty, files: [{ path: 'main.go', language: 'go', sha256: '0'.repeat(64), size: 12, content: 'package main' }] };

  for (const [label, bundle] of golden) {
    const a = await analyze(bundle);
    const b = await analyze(bundle);
    let parsed = null;
    try { parsed = JSON.parse(a.body); } catch (_) { /* reported below */ }
    check(a.status === 200 && parsed && validResult(parsed), `${label}: valid result (${parsed ? `${parsed.status}, ${parsed.findings.length} finding(s)` : `HTTP ${a.status}`})`,
      parsed ? ajv.errorsText(validResult.errors) : a.body.slice(0, 200));
    if (!parsed) continue;
    const strip = s => JSON.stringify({ ...JSON.parse(s), seconds: undefined });
    check(strip(a.body) === strip(b.body), `${label}: deterministic across two runs`);
    check(sortedLikeContract(parsed.findings), `${label}: findings in contract order`);
    const unknown = parsed.findings.filter(f => !threats[f.threat]).map(f => f.threat);
    check(unknown.length === 0, `${label}: threats are in contracts/threats.json`, `unknown: ${[...new Set(unknown)].join(', ')}`);
    check(parsed.analyzer.artifact_hash === health.artifact_hash, `${label}: result identity matches /v1/health`);
  }

  for (const [label, bundle] of [['empty bundle', empty], ['unsupported language only', goOnly]]) {
    const r = await analyze(bundle);
    let parsed = null;
    try { parsed = JSON.parse(r.body); } catch (_) { /* reported below */ }
    check(r.status === 200 && parsed && validResult(parsed) && ['not_applicable', 'ok', 'error'].includes(parsed.status),
      `${label}: contract status (${parsed ? parsed.status : `HTTP ${r.status}`})`);
  }

  console.log(failures === 0 ? '\nPASS — conforms to analyzer contract v1' : `\nFAIL — ${failures} check(s) failed`);
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.error(e); process.exit(2); });
