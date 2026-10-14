/**
 * MCP Secure — Analyzer registry (spec §5)
 * =========================================
 * Reads config/analyzers.json and resolves each slot to something callable:
 *   remote   a service implementing the contract (url set)
 *   builtin  an in-process implementation of the same contract
 *   none     not configured and no fallback → the slot reports "unavailable"
 *
 * Adding an analyzer = deploy a service + add one entry to the JSON file.
 */

const fs = require('fs');
const path = require('path');

const CONFIG_PATH = process.env.MCS_ANALYZERS_CONFIG
  || path.join(__dirname, '..', '..', '..', 'config', 'analyzers.json');

const BUILTINS = {
  text_heuristic: require('../analyzers/builtin/text_heuristic'),
  ingest_checks: require('../analyzers/builtin/ingest_checks'),
};

/** `${NAME:-default}` / `${NAME}` substitution from the environment. */
function expandEnv(value) {
  return String(value || '').replace(/\$\{([A-Z0-9_]+)(?::-([^}]*))?\}/g, (_, name, def) => {
    const v = process.env[name];
    return v !== undefined && v !== '' ? v : (def !== undefined ? def : '');
  });
}

function loadRegistry() {
  const cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  return cfg.analyzers.map(a => {
    const url = a.url !== undefined ? expandEnv(a.url).replace(/\/$/, '') : '';
    let mode = 'none';
    let builtin = null;
    if (a.builtin) { mode = 'builtin'; builtin = BUILTINS[a.builtin]; }
    else if (url) mode = 'remote';
    else if (a.fallback) { mode = 'builtin'; builtin = BUILTINS[a.fallback]; }
    if (mode === 'builtin' && !builtin) throw new Error(`analyzer '${a.id}': unknown builtin '${a.builtin || a.fallback}'`);
    return {
      id: a.id,
      stage: a.stage || 'analyze',
      kind: a.kind || 'code',
      required: !!a.required,
      when: a.when || null,
      timeoutMs: a.timeout_ms || 120000,
      mode,
      url,
      builtin,
      fallbackUsed: !a.builtin && mode === 'builtin',
    };
  });
}

module.exports = { loadRegistry, expandEnv, CONFIG_PATH };
