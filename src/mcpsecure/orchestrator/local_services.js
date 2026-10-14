/**
 * MCP Secure — local analyzer services for development
 * =====================================================
 * So that `npm start` is one command: when an analyzer slot points at a
 * localhost URL that is not answering, start the matching service from this
 * repository and wait for its /v1/health. Production deployments run the
 * services themselves and set MCS_SPAWN_ANALYZERS=0.
 *
 *   ast_taint  python3 ast_taint_analyzer/service.py              (stdlib only)
 *   model_b    model_b_service/.venv/bin/python model_b_service/serve.py
 *              (needs the venv from model_b_service/README.md; skipped with a
 *               warning when it is missing — the slot then reports unavailable
 *               and the policy refuses to PASS)
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const { loadRegistry } = require('./registry');

const ROOT = path.join(__dirname, '..', '..', '..');
const children = [];

const RECIPES = {
  ast_taint: port => ({
    cmd: process.env.MCS_PYTHON || 'python3',
    args: [path.join(ROOT, 'ast_taint_analyzer', 'service.py'), '--port', String(port)],
    cwd: ROOT,
  }),
  model_b: port => {
    const venv = path.join(ROOT, 'model_b_service', '.venv', 'bin', 'python');
    if (!fs.existsSync(venv)) return { missing: 'model_b_service/.venv not found — see model_b_service/README.md (Setup)' };
    return {
      cmd: venv,
      args: ['serve.py', '--port', String(port)],
      cwd: path.join(ROOT, 'model_b_service'),
      env: { HF_HUB_OFFLINE: process.env.HF_HUB_OFFLINE || '1' },
    };
  },
};

async function healthy(url) {
  try {
    const r = await fetch(`${url}/v1/health`, { signal: AbortSignal.timeout(2000) });
    return r.ok;
  } catch (_) {
    return false;
  }
}

async function waitHealthy(url, timeoutMs) {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    if (await healthy(url)) return true;
    await new Promise(r => setTimeout(r, 500));
  }
  return false;
}

/** Start missing local services; resolves when each is healthy or has given up. */
async function ensureLocalAnalyzers({ timeoutMs = 120000, log = console.log } = {}) {
  if (process.env.MCS_SPAWN_ANALYZERS === '0') return;
  const slots = loadRegistry().filter(s => s.mode === 'remote' && RECIPES[s.id]);
  await Promise.all(slots.map(async slot => {
    const u = new URL(slot.url);
    if (!['127.0.0.1', 'localhost'].includes(u.hostname)) return;
    if (await healthy(slot.url)) { log(`[MCS] analyzer ${slot.id} already running at ${slot.url}`); return; }
    const recipe = RECIPES[slot.id](Number(u.port));
    if (recipe.missing) { log(`[MCS] ⚠ analyzer ${slot.id} not started: ${recipe.missing}`); return; }
    log(`[MCS] starting analyzer ${slot.id} on ${slot.url} …`);
    const child = spawn(recipe.cmd, recipe.args, {
      cwd: recipe.cwd,
      env: { ...process.env, ...(recipe.env || {}) },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let tail = '';
    child.stderr.on('data', d => { tail = (tail + d).slice(-2000); });
    child.on('exit', code => {
      if (code) log(`[MCS] analyzer ${slot.id} exited with code ${code}: ${tail.trim().split('\n').slice(-2).join(' | ')}`);
    });
    children.push(child);
    const ok = await waitHealthy(slot.url, timeoutMs);
    log(ok ? `[MCS] analyzer ${slot.id} ready` : `[MCS] ⚠ analyzer ${slot.id} did not become healthy within ${timeoutMs / 1000}s`);
  }));
}

/**
 * Wait until every required remote analyzer answers /v1/health, or until
 * `timeoutMs` passes. The submission worker calls this before each job so a
 * cold start (Model B loading) or a crashed local service does not turn queued
 * submissions into fail-closed REVIEWs; a local service that is down is started again. After the timeout the scan runs anyway and the policy's
 * required_analyzer_unavailable rule applies, as before.
 */
async function waitForRequiredAnalyzers({ timeoutMs = Number(process.env.MCS_ANALYZER_WAIT_MS || 300000), log = console.log } = {}) {
  const slots = loadRegistry().filter(s => s.mode === 'remote' && s.required);
  const until = Date.now() + timeoutMs;
  let warned = false;
  for (;;) {
    const down = [];
    for (const s of slots) if (!(await healthy(s.url))) down.push(s.id);
    if (!down.length) return true;
    if (Date.now() >= until) {
      log(`[MCS] ⚠ scanning without ${down.join(', ')}: not healthy after ${Math.round(timeoutMs / 1000)}s`);
      return false;
    }
    if (!warned) {
      log(`[MCS] waiting for analyzer(s) ${down.join(', ')} before scanning …`);
      warned = true;
      await ensureLocalAnalyzers({ log }); // a local service that died (or never started) is started again
    }
    await new Promise(r => setTimeout(r, 1000));
  }
}

function stopLocalAnalyzers() {
  for (const c of children) { try { c.kill(); } catch (_) { /* gone */ } }
}

for (const sig of ['exit', 'SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    stopLocalAnalyzers();
    if (sig !== 'exit') process.exit(0);
  });
}

module.exports = { ensureLocalAnalyzers, stopLocalAnalyzers, waitForRequiredAnalyzers };
