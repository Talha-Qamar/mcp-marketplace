#!/usr/bin/env node
/**
 * Policy replay: re-decide the scans of an evaluation run under several
 * rulesets, without rescanning. Needs a run made after the `replay` record was
 * added to eval/run_eval.js.
 *
 *   node eval/replay.js run3 [--md]        compare the variants below on eval/results/run3.jsonl
 *
 * Variants are the current ruleset.json plus edits, so the comparison always
 * starts from what production runs.
 */

const fs = require('fs');
const path = require('path');
const { decide } = require('../src/mcpsecure/policy/engine');

const run = process.argv[2] || 'run3';
const MD = process.argv.includes('--md');
const rows = fs.readFileSync(path.join(__dirname, 'results', `${run}.jsonl`), 'utf8')
  .split('\n').filter(Boolean).map(l => JSON.parse(l)).filter(r => r.ok && r.replay);

const base = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'src', 'mcpsecure', 'ruleset.json'), 'utf8'));
const clone = o => JSON.parse(JSON.stringify(o));

function edit(fn) {
  const r = clone(base);
  fn(r);
  return r;
}
const rule = (r, id) => r.rules.find(x => x.id === id);
const withoutRule = (r, id) => { r.rules = r.rules.filter(x => x.id !== id); };
const ensureReachCap = r => {
  if (rule(r, 'unreachable_code_is_evidence')) return;
  const at = r.rules.findIndex(x => x.id === 'model_b_requires_corroboration');
  r.rules.splice(at, 0, { id: 'unreachable_code_is_evidence', type: 'cap_outside_reachable', slots: ['model_b'], cap: 0.25 });
};

const trust = (r, kinds, min, exclude = []) => Object.assign(rule(r, 'model_b_requires_corroboration'),
  { trusted_locations: kinds, trusted_min_score: min, trusted_exclude_threats: exclude });
const VARIANTS = {
  'v5 (AST corroboration only)': edit(r => { withoutRule(r, 'unreachable_code_is_evidence'); trust(r, [], 0); }),
  '+ unreachable = evidence': edit(r => { ensureReachCap(r); trust(r, [], 0); }),
};
VARIANTS['current ruleset.json'] = clone(base);
for (const min of [0.75, 0.85, 0.9, 0.95]) {
  VARIANTS[`handler ≥${min}`] = edit(r => { withoutRule(r, 'unreachable_code_is_evidence'); trust(r, ['tool_handler'], min); });
  VARIANTS[`handler ≥${min}, no sql_injection`] = edit(r => { withoutRule(r, 'unreachable_code_is_evidence'); trust(r, ['tool_handler'], min, ['sql_injection']); });
  VARIANTS[`unreachable + handler ≥${min}`] = edit(r => { ensureReachCap(r); trust(r, ['tool_handler'], min); });
  VARIANTS[`unreachable + handler/callee ≥${min}`] = edit(r => { ensureReachCap(r); trust(r, ['tool_handler', 'handler_callee'], min); });
}

const verdictOf = (r, ruleset) => decide(r.replay.slots, r.replay.bundle, ruleset).verdict;
const count = (xs, v) => xs.filter(x => x === v).length;
const pct = (n, d) => (d ? `${Math.round((100 * n) / d)}%` : '—');

const vuln = rows.filter(r => r.set === 'vuln' && r.version === 'vulnerable');
const fixedById = new Map(rows.filter(r => r.set === 'vuln' && r.version === 'fixed').map(r => [r.id, r]));
const benign = rows.filter(r => r.set === 'benign' && !r.by_design);
const byDesign = rows.filter(r => r.set === 'benign' && r.by_design);
const RANK = { PASS: 0, REVIEW: 1, FAIL: 2 };

const table = [];
for (const [name, rs] of Object.entries(VARIANTS)) {
  const v = vuln.map(r => verdictOf(r, rs));
  const pairs = vuln.filter(r => fixedById.has(r.id)).map(r => [verdictOf(r, rs), verdictOf(fixedById.get(r.id), rs)]);
  const b = benign.map(r => verdictOf(r, rs));
  const d = byDesign.map(r => verdictOf(r, rs));
  table.push({
    name,
    vulnFail: `${count(v, 'FAIL')}/${v.length} (${pct(count(v, 'FAIL'), v.length)})`,
    vulnCaught: `${v.length - count(v, 'PASS')}/${v.length}`,
    fixImproved: `${pairs.filter(([a, c]) => RANK[c] < RANK[a]).length}/${pairs.length}`,
    benignFail: `${count(b, 'FAIL')}/${b.length}`,
    benignReview: `${count(b, 'REVIEW')}/${b.length} (${pct(count(b, 'REVIEW'), b.length)})`,
    benignPass: `${count(b, 'PASS')}/${b.length}`,
    byDesign: `${count(d, 'FAIL')}F ${count(d, 'REVIEW')}R ${count(d, 'PASS')}P`,
  });
}

const cols = [['name', 'Ruleset'], ['vulnFail', 'Vulnerable → FAIL'], ['vulnCaught', 'Vulnerable not PASS'],
  ['fixImproved', 'Fix improves verdict'], ['benignFail', 'Benign FAIL'], ['benignReview', 'Benign REVIEW'],
  ['benignPass', 'Benign PASS'], ['byDesign', 'Exec-by-design']];
if (MD) {
  console.log(`| ${cols.map(c => c[1]).join(' | ')} |`);
  console.log(`|${cols.map(() => '---').join('|')}|`);
  for (const t of table) console.log(`| ${cols.map(c => t[c[0]]).join(' | ')} |`);
} else {
  console.table(table);
}

// Benign servers that a variant would FAIL, so a reviewer can judge them.
const last = Object.values(VARIANTS).filter((_, i, a) => i >= 2);
for (const rs of last) {
  const fails = benign.filter(r => verdictOf(r, rs) === 'FAIL').map(r => {
    const top = decide(r.replay.slots, r.replay.bundle, rs).effective_findings[0];
    return `${r.id}: ${top.slot}:${top.threat} ${top.effective_score.toFixed(2)} (${top.corroborated_by || ''})`;
  });
  if (fails.length) console.log(`\nbenign FAIL under "${Object.keys(VARIANTS)[Object.values(VARIANTS).indexOf(rs)]}":\n  ${fails.join('\n  ')}`);
}
