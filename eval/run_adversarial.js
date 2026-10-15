#!/usr/bin/env node
/**
 * Adversarial suite: eval/adversarial/<case>/ are small MCP servers, each
 * probing one boundary of the gate. expect.json says what a correct gate does:
 *
 *   PASS / REVIEW / FAIL   exact verdict
 *   DETECT                 not PASS, and (if `threat` is given) a finding of that threat at review level or above
 *   NOT_PASS / NOT_FAIL    anything but PASS / FAIL
 *
 * A case with `known_gap` (owner + reason) is a documented limitation: its
 * miss is reported but does not fail the run; if it starts passing, the run
 * says so, so the gap can be closed.
 *
 *   node eval/run_adversarial.js [--json]        exit 1 when a case without known_gap misses
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { runPipeline } = require('../src/mcpsecure/orchestrator/pipeline');
const { ensureLocalAnalyzers, stopLocalAnalyzers } = require('../src/mcpsecure/orchestrator/local_services');

const DIR = path.join(__dirname, 'adversarial');

function judge(expect, out) {
  const v = out.policy.verdict;
  const raw = out.slots.flatMap(s => (s.result.findings || []).map(f => ({ ...f, slot: s.slot })));
  const hit = expect.threat ? raw.find(f => f.threat === expect.threat && f.score >= 0.4) : null;
  switch (expect.expect) {
    case 'PASS': case 'REVIEW': case 'FAIL': return v === expect.expect;
    case 'DETECT': return v !== 'PASS' && (!expect.threat || !!hit || v === 'FAIL');
    case 'NOT_PASS': return v !== 'PASS';
    case 'NOT_FAIL': return v !== 'FAIL';
    default: throw new Error(`unknown expectation ${expect.expect}`);
  }
}

function materialize(caseDir, expect) {
  if (!expect.pad) return { dir: caseDir, cleanup: () => {} };
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mcs-adv-'));
  fs.cpSync(caseDir, tmp, { recursive: true });
  const f = path.join(tmp, expect.pad.file);
  fs.writeFileSync(f, fs.readFileSync(f, 'utf8').replace(expect.pad.marker, '# ' + 'x'.repeat(expect.pad.bytes)));
  return { dir: tmp, cleanup: () => fs.rmSync(tmp, { recursive: true, force: true }) };
}

(async () => {
  const asJson = process.argv.includes('--json');
  await ensureLocalAnalyzers({ log: () => {} });
  // Model A (tool-description text) is out of scope this iteration: a text case it would catch is
  // reported as out of scope, not as a regression, while the slot is disabled.
  const modelAOff = !require('../src/mcpsecure/orchestrator/registry').loadRegistry().some(s => s.id === 'model_a');
  const rows = [];
  for (const name of fs.readdirSync(DIR).sort()) {
    const caseDir = path.join(DIR, name);
    const expect = JSON.parse(fs.readFileSync(path.join(caseDir, 'expect.json'), 'utf8'));
    const m = materialize(caseDir, expect);
    try {
      const out = await runPipeline({ source: { kind: 'local', path: m.dir }, listing: { name } });
      const flags = out.slots.flatMap(s => (s.result.findings || []).filter(f => f.score >= 0.4)
        .map(f => `${s.slot}:${f.threat}:${f.score.toFixed(2)}`));
      rows.push({ case: name, group: expect.group, expect: expect.expect + (expect.threat ? `(${expect.threat})` : ''),
        verdict: out.policy.verdict, ok: judge(expect, out),
        knownGap: expect.known_gap || (modelAOff && expect.group === 'text' ? 'out of scope: Model A is disabled in this iteration' : null),
        rules: out.policy.reasons.map(r => r.rule), flags,
        notes: out.bundle.coverage.notes });
    } catch (e) {
      rows.push({ case: name, group: expect.group, expect: expect.expect, verdict: 'ERROR', ok: false, knownGap: null, rules: [], flags: [], notes: [e.message] });
    } finally {
      m.cleanup();
    }
  }
  stopLocalAnalyzers();
  if (asJson) console.log(JSON.stringify(rows, null, 1));
  else {
    for (const r of rows) {
      const mark = r.ok ? (r.knownGap ? '★' : '✓') : r.knownGap ? '○' : '✗';
      console.log(`${mark} ${r.case.padEnd(32)} ${r.expect.padEnd(34)} → ${r.verdict.padEnd(6)} ${r.rules.join(',')}${r.flags.length ? ' | ' + r.flags.join(' ') : ''}`);
    }
    const gaps = rows.filter(r => !r.ok && r.knownGap);
    console.log(`\n${rows.filter(r => r.ok).length}/${rows.length} as expected · ${gaps.length} known gap(s) (○) · ${rows.filter(r => !r.ok && !r.knownGap).length} regression(s) (✗)`);
    for (const g of gaps) console.log(`  ○ ${g.case}: ${g.knownGap}`);
    for (const r of rows.filter(x => x.ok && x.knownGap)) console.log(`  ★ ${r.case} now passes: remove its known_gap`);
  }
  process.exit(rows.every(r => r.ok || r.knownGap) ? 0 : 1);
})();
