/**
 * HTTP-level test: boots the real server on a temporary database and drives
 * the scan stream, the submission gate and admin decisions. Needs the
 * analyzer services (started automatically); skipped without the Model B venv.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const PORT = 3990 + Math.floor(Math.random() * 9);
const BASE = `http://127.0.0.1:${PORT}`;
const HAVE_MODEL_B = fs.existsSync(path.join(ROOT, 'model_b_service', '.venv', 'bin', 'python'));

function client() {
  let cookie = '';
  return async (method, url, body) => {
    const res = await fetch(BASE + url, {
      method,
      headers: { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const set = res.headers.get('set-cookie');
    if (set) cookie = set.split(';')[0];
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch (_) { /* SSE or HTML */ }
    return { status: res.status, json, text };
  };
}

async function waitState(call, id, done = ['approved', 'in_review', 'rejected', 'failed']) {
  for (let i = 0; i < 240; i++) {
    const r = await call('GET', `/api/v1/submissions/${id}`);
    if (done.includes(r.json.submission.state)) return r.json;
    await new Promise(res => setTimeout(res, 500));
  }
  throw new Error('submission did not finish');
}

test('marketplace API: scan stream, gate, supersede, admin decision', { skip: !HAVE_MODEL_B && 'Model B venv missing', timeout: 600000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcs-api-'));
  const server = spawn(process.execPath, ['server.js'], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(PORT), MCS_DB_PATH: path.join(dir, 'test.db'), SESSION_SECRET: 'test' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let log = '';
  server.stdout.on('data', d => { log += d; });
  server.stderr.on('data', d => { log += d; });
  try {
    for (let i = 0; i < 600 && !log.includes('running on'); i++) await new Promise(r => setTimeout(r, 250));
    assert.ok(log.includes('running on'), log);
    assert.match(log, /weather-tools: PASS \(expected PASS\) ✓/);

    // the streamed scan (SSE) carries stages and a result
    const stream = await fetch(`${BASE}/api/mcs/scan/stream?serverSlug=shell-runner`).then(r => r.text());
    assert.match(stream, /event: stage/);
    assert.match(stream, /event: result/);
    assert.match(stream, /"verdict":"FAIL"/);

    const alice = client();
    assert.equal((await alice('POST', '/api/auth/register', { username: 'alice', email: 'a@x.test', password: 'pw123456' })).status, 201);
    assert.equal((await alice('POST', '/api/servers', {})).status, 410); // no unscanned publishing

    const first = await alice('POST', '/api/v1/submissions', { name: 'Notes', slug: 'alice-notes', source: { kind: 'demo', name: 'db-helper' } });
    assert.equal(first.status, 202);
    assert.equal(first.json.server.listing_status, 'pending');
    const r1 = await waitState(alice, first.json.submission.id);
    assert.equal(r1.submission.state, 'in_review');
    assert.equal((await alice('GET', '/api/servers?limit=100')).json.servers.some(s => s.slug === 'alice-notes'), false);

    // a newer version supersedes the pending one
    const second = await alice('POST', '/api/v1/submissions', { name: 'Notes', slug: 'alice-notes', source: { kind: 'demo', name: 'db-helper' } });
    assert.equal((await alice('GET', `/api/v1/submissions/${first.json.submission.id}`)).json.submission.state, 'superseded');
    await waitState(alice, second.json.submission.id);

    // publishers cannot use local paths or other people's slugs
    assert.equal((await alice('POST', '/api/v1/submissions', { name: 'x', source: { kind: 'local', path: '/etc' } })).status, 400);
    assert.equal((await alice('GET', '/api/v1/review-queue')).status, 403);

    const admin = client();
    await admin('POST', '/api/auth/register', { username: 'admin1', email: 'adm@x.test', password: 'pw123456' });
    const Database = require('better-sqlite3');
    const db = new Database(path.join(dir, 'test.db'));
    db.prepare(`UPDATE users SET role = 'admin' WHERE username = 'admin1'`).run();
    db.close();

    const queue = (await admin('GET', '/api/v1/review-queue')).json;
    assert.deepEqual(queue.map(q => q.id), [second.json.submission.id]);
    assert.ok(queue[0].scan.policy.reasons.length > 0);
    assert.equal((await admin('POST', `/api/v1/submissions/${second.json.submission.id}/decision`, { decision: 'approve' })).status, 400);
    const ok = await admin('POST', `/api/v1/submissions/${second.json.submission.id}/decision`, { decision: 'approve', note: 'marketing copy only' });
    assert.equal(ok.json.submission.state, 'approved');
    assert.equal(ok.json.decisions[0].note, 'marketing copy only');
    assert.equal((await alice('GET', '/api/servers?limit=100')).json.servers.some(s => s.slug === 'alice-notes'), true);
  } finally {
    server.kill();
    await new Promise(r => server.on('exit', r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
