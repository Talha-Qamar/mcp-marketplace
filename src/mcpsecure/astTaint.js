/**
 * MCP Secure — Real AST Taint Analyzer bridge
 * ===========================================
 * REAL (not simulated). Shells out to the Part 2 Python analyzer in
 * `ast_taint_analyzer/` and maps its structured findings onto the
 * { score, evidence, fired } contract the policy engine already expects.
 *
 * The project's non-negotiable properties are preserved:
 *   OFFLINE       — a local subprocess. Nothing leaves the host.
 *   DETERMINISTIC — the analyzer is byte-reproducible for the same input;
 *                   see ast_taint_analyzer/tests/test_determinism.py.
 *   STATIC        — the candidate code is PARSED, never executed. We write it
 *                   to a temp file and pass the path as an argument; we never
 *                   run an interpreter from that directory.
 *
 * If Python or the analyzer package is unavailable, callers fall back to the
 * legacy regex heuristic and the evidence says so explicitly — the UI must
 * never imply real static analysis ran when it did not.
 */

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const ANALYZER_ROOT = path.join(__dirname, '..', '..', 'ast_taint_analyzer');
const ANALYZER_SRC = path.join(ANALYZER_ROOT, 'src');
const CONFIG_PY = path.join(ANALYZER_SRC, 'ast_taint', 'config.py');

const SUBPROCESS_TIMEOUT_MS = 20000;
const MAX_BUFFER = 8 * 1024 * 1024;

// `python` first (Windows), then the POSIX names, then the Windows launcher.
const PYTHON_CANDIDATES = process.env.MCS_PYTHON
  ? [process.env.MCS_PYTHON]
  : ['python', 'python3', 'py'];

let _python;          // undefined = not probed, null = unavailable
let _version = null;
let _configHash = null;

function childEnv() {
  return {
    ...process.env,
    PYTHONPATH: ANALYZER_SRC,
    PYTHONDONTWRITEBYTECODE: '1',
    PYTHONIOENCODING: 'utf-8',
  };
}

/**
 * Run the analyzer CLI. Exit code 1 means "a HIGH finding exists", which is a
 * RESULT, not a failure — execFileSync throws on it, so stdout is recovered
 * from the error. Any other non-zero status is a genuine failure.
 */
function runCli(python, args) {
  try {
    return execFileSync(python, ['-m', 'ast_taint', ...args], {
      encoding: 'utf8',
      timeout: SUBPROCESS_TIMEOUT_MS,
      env: childEnv(),
      windowsHide: true,
      maxBuffer: MAX_BUFFER,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (err) {
    if (err && err.status === 1 && typeof err.stdout === 'string') {
      return err.stdout;
    }
    throw err;
  }
}

/** Locate a working interpreter once, then cache the answer. */
function resolvePython() {
  if (_python !== undefined) return _python;

  for (const candidate of PYTHON_CANDIDATES) {
    try {
      execFileSync(candidate, ['-m', 'ast_taint', 'feature-names'], {
        encoding: 'utf8',
        timeout: SUBPROCESS_TIMEOUT_MS,
        env: childEnv(),
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      _python = candidate;
      _version = readVersion(candidate);
      return _python;
    } catch (_) {
      // try the next candidate
    }
  }

  _python = null;
  return _python;
}

function readVersion(python) {
  try {
    return execFileSync(
      python,
      ['-c', 'import ast_taint, sys; sys.stdout.write(ast_taint.__version__)'],
      { encoding: 'utf8', timeout: SUBPROCESS_TIMEOUT_MS, env: childEnv(), windowsHide: true }
    ).trim();
  } catch (_) {
    return 'unknown';
  }
}

/**
 * SHA-256 of the analyzer's detection configuration.
 *
 * config.py is the file that decides what is and is not a sink, so pinning its
 * hash in the attestation is what makes a verdict reproducible: change a sink
 * and the hash changes with it.
 */
function configHash() {
  if (_configHash !== null) return _configHash;
  try {
    _configHash = crypto.createHash('sha256').update(fs.readFileSync(CONFIG_PY)).digest('hex');
  } catch (_) {
    _configHash = null;
  }
  return _configHash;
}

function isAvailable() {
  return resolvePython() !== null;
}

// ─── Python source extraction ─────────────────────────────────────────────────
// The POC stores no source code: `tools` has name/description/input_schema and
// nothing else. What it does have is markdown `long_description` fields that
// embed implementation snippets. Those snippets are the real analysis target.

const FENCED_PYTHON = /```[ \t]*(?:python|py)[ \t]*\r?\n([\s\S]*?)```/gi;

// A line that plausibly starts a Python region at column 0.
const PY_START = /^(?:import\s+\w|from\s+[\w.]+\s+import\s|def\s+\w|async\s+def\s+\w|class\s+\w|@\w)/;

// A markdown heading at column 0. Indented `#` is a Python comment, not a
// heading, so the anchor matters.
const MD_HEADING = /^#{1,6}\s/;

function extractFenced(text) {
  const blocks = [];
  let match;
  FENCED_PYTHON.lastIndex = 0;
  while ((match = FENCED_PYTHON.exec(text)) !== null) {
    const block = match[1].trim();
    if (block) blocks.push(block);
  }
  return blocks.join('\n\n\n');
}

function extractUnfenced(text) {
  const lines = String(text).split(/\r?\n/);
  const collected = [];
  let capturing = false;

  for (const line of lines) {
    if (!capturing && PY_START.test(line)) capturing = true;
    if (!capturing) continue;
    if (MD_HEADING.test(line)) break;
    collected.push(line);
  }
  return collected.join('\n').trim();
}

/**
 * Pull analyzable Python out of a markdown blob.
 * Fenced ```python blocks win; an unfenced region is the fallback.
 * @param {string} text
 * @returns {string} source, or '' when there is nothing to analyse
 */
function extractPythonSource(text) {
  if (!text || typeof text !== 'string') return '';
  const fenced = extractFenced(text);
  if (fenced) return fenced;
  return extractUnfenced(text);
}

// ─── Analysis ─────────────────────────────────────────────────────────────────

function severityScore(severity, scores) {
  const table = scores || { high: 1.0, medium: 0.55, low: 0.25, none: 0.0 };
  const value = table[String(severity).toLowerCase()];
  return typeof value === 'number' ? value : 0;
}

function formatHit(toolName, hit) {
  const flow = [...(hit.path || []), `${hit.sink_name}()`].join(' → ');
  const sanitized = hit.sanitized ? ', sanitized' : '';
  return (
    `${toolName}(): tainted '${hit.source_param}' reaches ${hit.sink_name}() ` +
    `[${hit.category}] at line ${hit.lineno} — ${hit.n_hops} hop(s), ` +
    `${String(hit.severity).toUpperCase()}${sanitized} | flow: ${flow}`
  );
}

/**
 * Analyse Python source with the real taint engine.
 *
 * @param {string} source - Python source code (already extracted)
 * @param {object} [severityScores] - ruleset.astSeverityScores
 * @returns {{ok: true, score, evidence, hits, engine, version, configHash}
 *          |{ok: false, reason: string}}
 */
function analyze(source, severityScores) {
  const python = resolvePython();
  if (!python) {
    return { ok: false, reason: 'python interpreter or ast_taint package not available' };
  }

  let workdir;
  try {
    workdir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcs-ast-'));
    const candidate = path.join(workdir, 'candidate.py');
    fs.writeFileSync(candidate, source, 'utf8');

    // --all-functions because marketplace snippets rarely carry @tool decorators.
    const stdout = runCli(python, ['scan', candidate, '--json', '--all-functions']);
    const analyses = JSON.parse(stdout);

    const evidence = [];
    const hits = [];
    let score = 0;
    let parsed = false;

    for (const file of analyses) {
      if (!file.parse_ok) continue;
      parsed = true;
      for (const tool of file.tools || []) {
        for (const hit of tool.hits || []) {
          hits.push({ tool: tool.tool_name, ...hit });
          evidence.push(formatHit(tool.tool_name, hit));
          score = Math.max(score, severityScore(hit.severity, severityScores));
        }
      }
    }

    if (!parsed) {
      return { ok: false, reason: 'extracted text is not parseable Python' };
    }

    return {
      ok: true,
      score: parseFloat(score.toFixed(3)),
      evidence,
      hits,
      engine: 'ast-taint',
      version: _version,
      configHash: configHash(),
    };
  } catch (err) {
    return { ok: false, reason: `analyzer invocation failed: ${err.message}` };
  } finally {
    if (workdir) {
      try {
        fs.rmSync(workdir, { recursive: true, force: true });
      } catch (_) {
        /* best effort */
      }
    }
  }
}

module.exports = {
  analyze,
  extractPythonSource,
  isAvailable,
  configHash,
  ANALYZER_ROOT,
  get version() {
    resolvePython();
    return _version;
  },
};
