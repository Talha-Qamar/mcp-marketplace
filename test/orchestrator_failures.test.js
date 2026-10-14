/**
 * Analyzer failure modes: whatever an analyzer does wrong, the orchestrator
 * reports it as a status and the policy refuses to PASS. Uses stub analyzer
 * services on random ports.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { runSlot } = require('../src/mcpsecure/orchestrator/client');
const { decide } = require('../src/mcpsecure/policy/engine');
const ruleset = require('../src/mcpsecure/ruleset.json');

const HEALTH = {
  id: 'stub', display_name: 'Stub', version: '1', artifact_hash: 'sha256:' + 'a'.repeat(64), engine: 'model',
  consumes: ['files'], languages: ['python'], threats: ['command_injection'], contract_version: '1',
};
const GOOD = { analyzer: { id: 'stub', version: '1', artifact_hash: HEALTH.artifact_hash, engine: 'model' }, status: 'ok',
  coverage: { units_total: 1, units_analyzed: 1, languages: ['python'], notes: [] }, findings: [] };

function stub(behaviour) {
  return new Promise(resolve => {
    const server = http.createServer((req, res) => {
      const send = (code, body) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(typeof body === 'string' ? body : JSON.stringify(body)); };
      if (req.url === '/v1/health') return behaviour.health ? behaviour.health(send) : send(200, HEALTH);
      req.resume();
      req.on('end', () => behaviour.analyze(send));
    });
    server.listen(0, '127.0.0.1', () => resolve({ url: `http://127.0.0.1:${server.address().port}`, close: () => server.close() }));
  });
}

const slotFor = (url, timeoutMs = 2000) => ({ id: 'model_b', kind: 'code', required: true, mode: 'remote', url, timeoutMs });
const bundle = { files: [{ path: 's.py' }], tools: [], coverage: { tool_discovery: 'full', notes: [], skipped_code: [], unresolved_descriptions: [] } };

async function verdictWith(behaviour, timeoutMs) {
  const s = await stub(behaviour);
  try {
    const r = await runSlot(slotFor(s.url, timeoutMs), bundle);
    const others = [
      { slot: 'ast_taint', kind: 'code', required: true, result: { ...GOOD, analyzer: { ...GOOD.analyzer, id: 'ast_taint' } } },
      { slot: 'model_a', kind: 'text', required: true, result: GOOD },
    ];
    return { slot: r, verdict: decide([others[0], r, others[1]], bundle, { ...ruleset, analyzerPins: {} }).verdict };
  } finally { s.close(); }
}

test('a well-behaved analyzer passes through', async () => {
  const { slot, verdict } = await verdictWith({ analyze: send => send(200, GOOD) });
  assert.equal(slot.result.status, 'ok');
  assert.equal(verdict, 'PASS');
});

for (const [name, behaviour, timeout] of [
  ['HTTP 500', { analyze: send => send(500, { error: 'boom' }) }],
  ['invalid JSON', { analyze: send => send(200, '{not json') }],
  ['schema-violating result (score as a string)', { analyze: send => send(200, { ...GOOD, findings: [{ finding_id: 'sha256:' + 'b'.repeat(64), threat: 'command_injection', score: 'high', severity: 'high', location: { file: 's.py', line: 1, function: null, tool_id: null }, summary: 'x' }] }) }],
  ['identity changed between health and analyze', { analyze: send => send(200, { ...GOOD, analyzer: { ...GOOD.analyzer, artifact_hash: 'sha256:' + 'c'.repeat(64) } }) }],
  ['invalid /v1/health', { health: send => send(200, { id: 'stub' }), analyze: send => send(200, GOOD) }],
  ['hangs past the timeout', { analyze: () => {} }, 300],
]) {
  test(`analyzer failure → error status and no PASS: ${name}`, async () => {
    const { slot, verdict } = await verdictWith(behaviour, timeout);
    assert.equal(slot.result.status, 'error', JSON.stringify(slot.result));
    assert.equal(verdict, 'REVIEW');
  });
}

test('an unreachable analyzer is an error, not a crash', async () => {
  const r = await runSlot(slotFor('http://127.0.0.1:9'), bundle);
  assert.equal(r.result.status, 'error');
  assert.match(r.result.error, /unreachable/);
});
