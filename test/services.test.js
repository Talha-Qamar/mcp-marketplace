/**
 * Analyzer services started by `npm start` outlive a crashed parent (the
 * resilience test SIGKILLs it). Their stderr is then a closed pipe, and a log
 * write must not break the HTTP responses: before the fix every request got
 * "socket hang up" and every later scan fell back to REVIEW.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('child_process');
const path = require('path');

const ROOT = path.join(__dirname, '..');

async function health(url) {
  try {
    const r = await fetch(`${url}/v1/health`, { signal: AbortSignal.timeout(2000) });
    return r.status;
  } catch (e) {
    return e.cause ? e.cause.code || e.cause.message : e.message;
  }
}

test('the AST service keeps answering after its stderr pipe is closed', async () => {
  const port = 8790 + Math.floor(Math.random() * 100);
  const url = `http://127.0.0.1:${port}`;
  const child = spawn(process.env.MCS_PYTHON || 'python3', [path.join(ROOT, 'ast_taint_analyzer', 'service.py'), '--port', String(port)],
    { cwd: ROOT, stdio: ['ignore', 'ignore', 'pipe'] });
  try {
    let up = false;
    for (let i = 0; i < 60 && !up; i++) { up = (await health(url)) === 200; if (!up) await new Promise(r => setTimeout(r, 250)); }
    assert.ok(up, 'service did not start');
    child.stderr.destroy(); // what the service sees when its parent dies
    await new Promise(r => setTimeout(r, 200));
    for (let i = 0; i < 3; i++) assert.equal(await health(url), 200);
  } finally {
    child.kill('SIGKILL');
  }
});
