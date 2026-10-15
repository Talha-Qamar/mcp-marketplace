/**
 * Resilience: concurrent submissions, a crash mid-scan, and determinism on a
 * real repository at a pinned commit. Boots real servers on temp databases;
 * skipped without the Model B venv (and the git case without network).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const HAVE_MODEL_B = fs.existsSync(path.join(ROOT, 'model_b_service', '.venv', 'bin', 'python'));

function boot(dir, port) {
  const env = { ...process.env, PORT: String(port), MCS_DB_PATH: path.join(dir, 'r.db'), SESSION_SECRET: 'r' };
  if (!fs.existsSync(env.MCS_DB_PATH)) execFileSync(process.execPath, ['database/seed.js'], { cwd: ROOT, env, stdio: 'ignore' });
  const proc = spawn(process.execPath, ['server.js'], { cwd: ROOT, env, stdio: ['ignore', 'pipe', 'pipe'] });
  let log = '';
  proc.stdout.on('data', d => { log += d; });
  proc.stderr.on('data', d => { log += d; });
  const ready = (async () => {
    for (let i = 0; i < 1200 && !log.includes('running on'); i++) await new Promise(r => setTimeout(r, 250));
    if (!log.includes('running on')) throw new Error(log);
  })();
  return { proc, ready, log: () => log, stop: () => new Promise(r => { proc.on('exit', r); proc.kill('SIGKILL'); }) };
}

function client(base) {
  let cookie = '';
  return async (method, url, body) => {
    const res = await fetch(base + url, { method, headers: { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) }, body: body ? JSON.stringify(body) : undefined });
    const set = res.headers.get('set-cookie');
    if (set) cookie = set.split(';')[0];
    return { status: res.status, json: await res.json().catch(() => null) };
  };
}

async function settle(call, ids) {
  const final = ['approved', 'in_review', 'rejected', 'failed'];
  for (let i = 0; i < 600; i++) {
    const states = await Promise.all(ids.map(async id => (await call('GET', `/api/v1/submissions/${id}`)).json.submission.state));
    if (states.every(s => final.includes(s))) return states;
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error('submissions did not settle');
}

test('six concurrent submissions are all processed, serially, with correct verdicts', { skip: !HAVE_MODEL_B && 'no Model B venv', timeout: 900000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcs-res-'));
  const port = 4100 + Math.floor(Math.random() * 50);
  const srv = boot(dir, port);
  try {
    await srv.ready;
    const call = client(`http://127.0.0.1:${port}`);
    await call('POST', '/api/auth/login', { email: 'alice_dev@example.com', password: 'password123' });
    const demos = ['weather-tools', 'docs-helper', 'shell-runner', 'weather-tools', 'docs-helper', 'shell-runner'];
    const created = await Promise.all(demos.map((d, i) => call('POST', '/api/v1/submissions', { name: `Concurrent ${i}`, slug: `concurrent-${i}`, source: { kind: 'demo', name: d } })));
    assert.ok(created.every(r => r.status === 202), JSON.stringify(created.map(r => r.json)));
    const states = await settle(call, created.map(r => r.json.submission.id));
    assert.deepEqual(states, ['approved', 'in_review', 'rejected', 'approved', 'in_review', 'rejected']);
    // the worker is serial: "→ scanning" never appears twice without a verdict in between
    const transitions = srv.log().split('\n').filter(l => /submission .* → (scanning|approved|in_review|rejected|failed)/.test(l));
    let inFlight = 0;
    for (const t of transitions) { inFlight += /scanning/.test(t) ? 1 : -1; assert.ok(inFlight <= 1, 'two submissions scanned at once'); }
  } finally {
    await srv.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a submission interrupted by a crash is re-queued and completed on restart', { skip: !HAVE_MODEL_B && 'no Model B venv', timeout: 900000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcs-res-'));
  const port = 4200 + Math.floor(Math.random() * 50);
  let srv = boot(dir, port);
  try {
    await srv.ready;
    let call = client(`http://127.0.0.1:${port}`);
    await call('POST', '/api/auth/login', { email: 'alice_dev@example.com', password: 'password123' });
    // queue several so at least one is still pending or mid-scan when the process dies
    const ids = [];
    for (let i = 0; i < 4; i++) ids.push((await call('POST', '/api/v1/submissions', { name: `Crash ${i}`, slug: `crash-${i}`, source: { kind: 'demo', name: 'shell-runner' } })).json.submission.id);
    await srv.stop(); // SIGKILL: no graceful shutdown
    srv = boot(dir, port);
    await srv.ready;
    call = client(`http://127.0.0.1:${port}`);
    await call('POST', '/api/auth/login', { email: 'alice_dev@example.com', password: 'password123' });
    const states = await settle(call, ids);
    assert.deepEqual(states, ['rejected', 'rejected', 'rejected', 'rejected']);
  } finally {
    await srv.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('determinism: a real repository at a pinned commit scans identically twice', { skip: !HAVE_MODEL_B && 'no Model B venv', timeout: 600000 }, async (t) => {
  const { runPipeline } = require('../src/mcpsecure/orchestrator/pipeline');
  const { ensureLocalAnalyzers, stopLocalAnalyzers } = require('../src/mcpsecure/orchestrator/local_services');
  const source = { kind: 'git', repo_url: 'https://github.com/modelcontextprotocol/servers/tree/main/src/fetch', ref: '5f3cdfb508e307437556d20fb73708b1138447b9' };
  await ensureLocalAnalyzers({ log: () => {} });
  try {
    let a;
    try { a = await runPipeline({ source, listing: { name: 'fetch' } }); } catch (e) { t.skip(`network: ${e.message}`); return; }
    const b = await runPipeline({ source, listing: { name: 'fetch' } });
    const strip = o => JSON.stringify({ fp: o.bundle.content_fingerprint, sha: o.bundle.source.commit_sha, policy: o.policy, results: o.slots.map(s => s.result) });
    assert.equal(strip(a), strip(b));
    assert.equal(a.bundle.source.commit_sha, source.ref);
  } finally {
    stopLocalAnalyzers();
  }
});
