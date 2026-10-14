/**
 * MCP Secure — Analyzer contract client (spec §6)
 * ================================================
 * Calls one registry slot and always returns a slot result; an analyzer that
 * cannot be reached is reported as status "error" (fail-closed), never thrown.
 */

const http = require('http');
const https = require('https');
const Ajv = require('ajv/dist/2020');

const RETRY_DELAY_MS = 500;

// Responses are untrusted input too: a buggy or compromised analyzer must not
// be able to feed malformed findings into the policy. Invalid → status "error".
const ajv = new Ajv({ allErrors: true, strict: false });
const validResult = ajv.compile(require('../../../contracts/analyzer-result.schema.json'));
const validHealth = ajv.compile(require('../../../contracts/analyzer-health.schema.json'));

// node:http rather than global fetch: fetch (undici) gives up after 300 s
// waiting for response headers, whatever the slot's timeout_ms says.
function fetchJson(url, init, timeoutMs) {
  const u = new URL(url);
  const lib = u.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const req = lib.request(u, { method: init.method || 'GET', headers: init.headers || {} }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('error', reject);
      res.on('end', () => {
        clearTimeout(timer);
        if (res.statusCode < 200 || res.statusCode > 299) return reject(new Error(`HTTP ${res.statusCode} from ${url}`));
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch (e) { reject(e); }
      });
    });
    const timer = setTimeout(() => {
      const err = new Error(`timed out after ${Math.round(timeoutMs / 1000)}s`);
      err.name = 'TimeoutError';
      req.destroy(err);
    }, timeoutMs);
    req.on('error', err => { clearTimeout(timer); reject(err); });
    req.end(init.body);
  });
}

/** One retry, for connection-level failures only (a service restarting). */
async function withRetry(fn) {
  try {
    return await fn();
  } catch (err) {
    if (err && (err.name === 'TimeoutError' || /HTTP \d+/.test(err.message))) throw err;
    await new Promise(r => setTimeout(r, RETRY_DELAY_MS));
    return fn();
  }
}

function errorResult(slot, message, identity) {
  return {
    analyzer: identity || { id: slot.id, version: 'unknown', artifact_hash: null, engine: 'unknown' },
    status: 'error',
    error: message,
    coverage: { units_total: 0, units_analyzed: 0, languages: [], notes: [] },
    findings: [],
  };
}

/**
 * @returns {Promise<{ slot, required, kind, mode, health, result }>}
 */
async function runSlot(slot, bundle, context = {}) {
  const base = { slot: slot.id, required: slot.required, kind: slot.kind, mode: slot.mode, fallbackUsed: slot.fallbackUsed };

  if (slot.mode === 'none') {
    return { ...base, health: null, result: { ...errorResult(slot, 'not configured'), status: 'unavailable' } };
  }
  if (slot.mode === 'builtin') {
    try {
      return { ...base, health: slot.builtin.health(), result: slot.builtin.analyze(bundle, context) };
    } catch (e) {
      return { ...base, health: null, result: errorResult(slot, `builtin failed: ${e.message}`) };
    }
  }

  let health = null;
  try {
    health = await withRetry(() => fetchJson(`${slot.url}/v1/health`, {}, 10000));
  } catch (e) {
    return { ...base, health: null, result: errorResult(slot, `unreachable at ${slot.url} (${e.message})`) };
  }
  if (!validHealth(health)) {
    return { ...base, health: null, result: errorResult(slot, `invalid /v1/health response: ${ajv.errorsText(validHealth.errors)}`) };
  }
  try {
    const result = await withRetry(() => fetchJson(`${slot.url}/v1/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bundle, context }),
    }, slot.timeoutMs));
    const identity = { id: health.id, version: health.version, artifact_hash: health.artifact_hash, engine: health.engine };
    if (!validResult(result)) {
      return { ...base, health, result: errorResult(slot, `invalid analyzer response: ${ajv.errorsText(validResult.errors).slice(0, 300)}`, identity) };
    }
    if (result.analyzer.artifact_hash !== health.artifact_hash) {
      return { ...base, health, result: errorResult(slot, 'analyzer identity changed between /v1/health and /v1/analyze', identity) };
    }
    return { ...base, health, result };
  } catch (e) {
    const identity = { id: health.id, version: health.version, artifact_hash: health.artifact_hash, engine: health.engine };
    return { ...base, health, result: errorResult(slot, `analyze failed (${e.message})`, identity) };
  }
}

module.exports = { runSlot };
