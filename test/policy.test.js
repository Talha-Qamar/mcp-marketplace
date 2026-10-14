const test = require('node:test');
const assert = require('node:assert/strict');
const { decide } = require('../src/mcpsecure/policy/engine');
const ruleset = require('../src/mcpsecure/ruleset.json');

const bundle = (over = {}) => ({ files: [{ path: 's.py' }], coverage: { tool_discovery: 'full', notes: [] }, ...over });
const fn = (start, end) => ({ name: 'f', start_line: start, end_line: end });
const finding = (id, threat, score, severity, file = 's.py', span = fn(1, 10)) => ({
  finding_id: id, threat, score, severity, location: { file, line: span.start_line, function: span, tool_id: null }, summary: id,
});
const slot = (id, kind, status, findings = [], required = true) => ({
  slot: id, kind, required, result: { status, findings, coverage: { units_total: 1, units_analyzed: status === 'ok' ? 1 : 0, notes: [] } },
});
const clean = () => [slot('ast_taint', 'code', 'ok'), slot('model_b', 'code', 'ok'), slot('model_a', 'text', 'ok')];

test('clean results PASS with no reasons', () => {
  const d = decide(clean(), bundle(), ruleset);
  assert.equal(d.verdict, 'PASS');
  assert.deepEqual(d.reasons, []);
});

test('a required analyzer that did not run blocks PASS (fail-closed)', () => {
  const s = clean();
  s[1] = slot('model_b', 'code', 'unavailable');
  const d = decide(s, bundle(), ruleset);
  assert.equal(d.verdict, 'REVIEW');
  assert.equal(d.reasons[0].rule, 'required_analyzer_unavailable');
});

test('no code coverage (e.g. a Go server) is REVIEW, never PASS', () => {
  const s = [slot('ast_taint', 'code', 'not_applicable'), slot('model_b', 'code', 'not_applicable'), slot('model_a', 'text', 'ok')];
  const d = decide(s, bundle({ files: [] }), ruleset);
  assert.equal(d.verdict, 'REVIEW');
  assert.ok(d.reasons.some(r => r.rule === 'insufficient_code_coverage'));
});

test('no MCP tools discovered is REVIEW', () => {
  const d = decide(clean(), bundle({ coverage: { tool_discovery: 'none', notes: [] } }), ruleset);
  assert.equal(d.verdict, 'REVIEW');
  assert.ok(d.reasons.some(r => r.rule === 'no_tools_discovered'));
});

test('an AST high finding hard-fails', () => {
  const s = clean();
  s[0] = slot('ast_taint', 'code', 'ok', [finding('a1', 'command_injection', 1.0, 'high')]);
  const d = decide(s, bundle(), ruleset);
  assert.equal(d.verdict, 'FAIL');
  assert.ok(d.reasons.some(r => r.rule === 'ast_high_hard_fail'));
});

test('an uncorroborated Model B fail-level finding is capped to REVIEW', () => {
  const s = clean();
  s[1] = slot('model_b', 'code', 'ok', [finding('b1', 'sql_injection', 0.9, 'high')]);
  const d = decide(s, bundle(), ruleset);
  assert.equal(d.verdict, 'REVIEW');
  assert.equal(d.effective_findings[0].effective_score, 0.55);
});

test('an uncorroborated Model B review-level finding becomes evidence only', () => {
  const s = clean();
  s[1] = slot('model_b', 'code', 'ok', [finding('b1', 'path_traversal', 0.6, 'medium')]);
  assert.equal(decide(s, bundle(), ruleset).verdict, 'PASS');
});

test('Model B keeps its score when AST corroborates in an overlapping function of the same file', () => {
  const s = clean();
  s[0] = slot('ast_taint', 'code', 'ok', [finding('a1', 'path_traversal', 0.55, 'medium', 's.py', fn(3, 8))]);
  s[1] = slot('model_b', 'code', 'ok', [finding('b1', 'path_traversal', 0.9, 'high', 's.py', fn(1, 10))]);
  const d = decide(s, bundle(), ruleset);
  assert.equal(d.verdict, 'FAIL');
  assert.equal(d.effective_findings.find(e => e.finding_id === 'b1').corroborated_by, 'a1');
});

test('corroboration needs the same file and the same threat', () => {
  const s = clean();
  s[0] = slot('ast_taint', 'code', 'ok', [finding('a1', 'path_traversal', 0.55, 'medium', 'other.py', fn(1, 10))]);
  s[1] = slot('model_b', 'code', 'ok', [finding('b1', 'path_traversal', 0.9, 'high', 's.py', fn(1, 10)), finding('b2', 'ssrf', 0.9, 'high', 'other.py', fn(1, 10))]);
  const d = decide(s, bundle(), ruleset);
  assert.equal(d.verdict, 'REVIEW');
  assert.ok(d.effective_findings.every(e => e.slot !== 'model_b' || e.effective_score === 0.55));
});

test('the policy is deterministic', () => {
  const s = clean();
  s[1] = slot('model_b', 'code', 'ok', [finding('b1', 'sql_injection', 0.9, 'high'), finding('b0', 'ssrf', 0.5, 'medium')]);
  assert.equal(JSON.stringify(decide(s, bundle(), ruleset)), JSON.stringify(decide(s, bundle(), ruleset)));
});

test('a Model B whose artifact hash is not pinned by the ruleset cannot PASS', () => {
  const s = clean();
  s[1].result.analyzer = { id: 'model_b', artifact_hash: 'sha256:' + '0'.repeat(64) };
  const d = decide(s, bundle(), ruleset);
  assert.equal(d.verdict, 'REVIEW');
  assert.ok(d.reasons.some(r => r.rule === 'unpinned_analyzer_version'));
  s[1].result.analyzer.artifact_hash = ruleset.analyzerPins.model_b;
  assert.equal(decide(s, bundle(), ruleset).verdict, 'PASS');
});

test('skipped code files and runtime-built descriptions block PASS (policy-v5)', () => {
  const d1 = decide(clean(), bundle({ coverage: { tool_discovery: 'full', notes: [], skipped_code: [{ path: 'big.py', reason: 'over 400000 bytes' }] } }), ruleset);
  assert.equal(d1.verdict, 'REVIEW');
  assert.ok(d1.reasons.some(r => r.rule === 'source_not_fully_analysed'));
  const d2 = decide(clean(), bundle({ coverage: { tool_discovery: 'partial', notes: [], unresolved_descriptions: ['s.py#t'] } }), ruleset);
  assert.equal(d2.verdict, 'REVIEW');
  assert.ok(d2.reasons.some(r => r.rule === 'runtime_descriptions'));
});

test('a code analyzer that ran counts as coverage even with nothing to score', () => {
  const s = clean();
  s[0] = slot('ast_taint', 'code', 'not_applicable');
  s[1] = { ...slot('model_b', 'code', 'ok'), result: { status: 'ok', findings: [], coverage: { units_total: 0, units_analyzed: 0, notes: [] } } };
  assert.equal(decide(s, bundle(), ruleset).verdict, 'PASS');
});
