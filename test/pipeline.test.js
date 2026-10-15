/**
 * Regression gate (spec §7, Appendix A): the six demo scans must keep their
 * verdicts. Needs the analyzer services (started automatically when the
 * Model B venv exists); skipped otherwise.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { runPipeline } = require('../src/mcpsecure/orchestrator/pipeline');
const { ensureLocalAnalyzers, stopLocalAnalyzers } = require('../src/mcpsecure/orchestrator/local_services');
const { loadRegistry } = require('../src/mcpsecure/orchestrator/registry');
const { DEMO_SERVERS } = require('../src/mcpsecure/seed');

// [without bait, with the _bait/ rug-pull overlay]; null = no bait overlay for this server.
// db-helper's code is safe (its manipulative descriptions are Model A's job, out of scope).
const EXPECTED = {
  'weather-tools': ['PASS', 'FAIL'],
  'db-helper': ['PASS', 'FAIL'],
  'docs-helper': ['REVIEW', null],
  'shell-runner': ['FAIL', 'FAIL'],
};

async function servicesUp() {
  await ensureLocalAnalyzers({ log: () => {} });
  const remote = loadRegistry().filter(s => s.mode === 'remote' && s.required);
  const ok = await Promise.all(remote.map(s => fetch(`${s.url}/v1/health`, { signal: AbortSignal.timeout(2000) }).then(r => r.ok, () => false)));
  return ok.every(Boolean);
}

test('demo verdicts (with and without bait-and-switch)', { timeout: 300000 }, async (t) => {
  if (!(await servicesUp())) {
    stopLocalAnalyzers(); // the AST service may have started; a live child keeps the test process from exiting
    t.skip('analyzer services not available (see model_b_service/README.md)');
    return;
  }
  try {
    for (const demo of DEMO_SERVERS) {
      for (const [i, bait] of [false, true].entries()) {
        if (EXPECTED[demo.slug][i] === null) continue;
        const out = await runPipeline({
          source: { kind: 'local', path: `demo_servers/${demo.slug}`, overlay: bait ? `demo_servers/_bait/${demo.slug}` : undefined },
          listing: { name: demo.name, description: demo.description },
        });
        assert.equal(out.policy.verdict, EXPECTED[demo.slug][i], `${demo.slug}${bait ? ' (bait)' : ''}: ${JSON.stringify(out.policy.reasons)}`);
      }
    }
  } finally {
    stopLocalAnalyzers();
  }
});
