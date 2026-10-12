/**
 * MCP Secure — Deterministic Scan Engine
 * =======================================
 * AST taint is the real Part 2 analyzer (Python, regex fallback otherwise).
 * Model B is the real trained classifier when MODEL_B_URL is set (simulated
 * heuristic otherwise); its findings are combined with the AST hits under
 * ruleset.modelBPolicy. Model A is still a deterministic heuristic.
 * The policy engine logic is identical to production intent.
 *
 * simulateScan(content) → ScanRecord   (name kept for existing callers)
 *
 * Heuristics are VISIBLE and TRANSPARENT — the UI shows exactly WHY
 * a verdict was reached via the evidence[] arrays.
 */

const mcscrpyto = require('./crypto');
const astTaint = require('./astTaint');
const path = require('path');
const fs = require('fs');

// Load ruleset once at module init
const RULESET_PATH = path.join(__dirname, 'ruleset.json');
const RULESET = JSON.parse(fs.readFileSync(RULESET_PATH, 'utf8'));
const RULESET_HASH = mcscrpyto.sha256hex(fs.readFileSync(RULESET_PATH, 'utf8'));

// ─── Analyzer 1: AST Taint (command injection — hard signal) ──────────────────
// REAL when the candidate contains Python: runAstTaint() delegates to the
// Part 2 analyzer in ast_taint_analyzer/ — a genuine Python AST taint engine
// with parameter-level source tracking, alias resolution, sanitizer awareness
// and a frozen severity table.
//
// The regex heuristic below is retained for two cases only, and is labelled
// SIMULATED in the evidence whenever it is the one that ran:
//   1. non-Python servers (JS/TS), which the Python analyzer cannot parse
//   2. environments with no usable Python interpreter
//
// Keeping it means a missing Python install degrades the scan instead of
// breaking the marketplace.

const DANGEROUS_SINKS = [
  { pattern: /os\.system\s*\(/, label: 'os.system()' },
  { pattern: /subprocess\s*\.\s*(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True/, label: 'subprocess(shell=True)' },
  { pattern: /eval\s*\(/, label: 'eval()' },
  { pattern: /exec\s*\(/, label: 'exec()' },
  { pattern: /\bspawn\s*\(/, label: 'spawn()' },
  { pattern: /execSync\s*\(/, label: 'execSync()' },
  { pattern: /child_process\.exec\s*\(/, label: 'child_process.exec()' },
];

const TAINT_INDICATORS = [
  { pattern: /\+\s*\w+/, label: 'string concatenation with variable' },
  { pattern: /f["'].*\{/, label: 'f-string with variable interpolation' },
  { pattern: /\$\{/, label: 'template literal interpolation' },
  { pattern: /format\s*\(/, label: '.format() with variable' },
  { pattern: /\%\s*\w+/, label: '% string formatting with variable' },
];

/**
 * Dispatcher. Prefers the real Python AST taint analyzer; falls back to the
 * regex heuristic only when there is no Python to analyse or no interpreter.
 *
 * @param {string} code - the candidate's text corpus (markdown + snippets)
 * @returns {{ score, evidence, fired, engine, hits?, version?, configHash? }}
 */
function runAstTaint(code) {
  const source = astTaint.extractPythonSource(code);

  if (source) {
    const real = astTaint.analyze(source, RULESET.astSeverityScores);
    if (real.ok) {
      const header = `engine: ast-taint v${real.version} (REAL static taint analysis, config ${String(real.configHash).slice(0, 12)}…)`;
      const body = real.evidence.length > 0
        ? real.evidence
        : ['No tainted data flow to dangerous sinks detected in the analysed Python source'];
      return {
        score: real.score,
        evidence: [header, ...body],
        fired: real.score >= 0.6,
        engine: 'ast-taint',
        version: real.version,
        configHash: real.configHash,
        hits: real.hits,
      };
    }
    // Python was present but the analyzer could not run — say so, then degrade.
    const degraded = runAstTaintHeuristic(code);
    return {
      ...degraded,
      engine: 'heuristic-fallback',
      evidence: [
        `engine: regex heuristic (SIMULATED) — real analyzer unavailable: ${real.reason}`,
        ...degraded.evidence,
      ],
    };
  }

  // No Python in the candidate at all (e.g. a TypeScript server).
  const heuristic = runAstTaintHeuristic(code);
  return {
    ...heuristic,
    engine: 'heuristic',
    evidence: [
      'engine: regex heuristic (SIMULATED) — no analysable Python source found in candidate',
      ...heuristic.evidence,
    ],
  };
}

/**
 * SIMULATED AST taint analyzer (legacy fallback).
 * Returns deterministic results based on string heuristics.
 * @param {string} code
 * @returns {{ score: number, evidence: string[], fired: boolean }}
 */
function runAstTaintHeuristic(code) {
  const evidence = [];
  let maxScore = 0;

  for (const sink of DANGEROUS_SINKS) {
    if (sink.pattern.test(code)) {
      for (const taint of TAINT_INDICATORS) {
        if (taint.pattern.test(code)) {
          const evidenceStr = `tainted input reaches ${sink.label} via ${taint.label}`;
          if (!evidence.includes(evidenceStr)) {
            evidence.push(evidenceStr);
          }
          maxScore = 1.0;
        }
      }
      // Even without explicit taint marker, sink alone is suspicious
      if (maxScore < 0.6) {
        evidence.push(`dangerous sink ${sink.label} detected (manual taint review needed)`);
        maxScore = Math.max(maxScore, 0.6);
      }
    }
  }

  return {
    score: maxScore,
    evidence,
    fired: maxScore >= 0.6,
  };
}

// ─── Analyzer 2: Model B Code (command injection — learned signal) ─────────────
// SIMULATED (POC): In production this is a fine-tuned code LLM (Model B) that
// detects obfuscated injection patterns that static analysis misses. Here we
// reproduce its key behaviors deterministically.

const OBFUSCATION_PATTERNS = [
  { pattern: /getattr\s*\(/, label: 'getattr() dynamic attribute access (obfuscation signal)' },
  { pattern: /base64/, label: 'base64 encoding present (payload obfuscation)' },
  { pattern: /['"]\s*\+\s*['"]/, label: 'split-string concatenation (evasion pattern)' },
  { pattern: /chr\s*\(/, label: 'chr() character encoding (obfuscation)' },
  { pattern: /\\x[0-9a-fA-F]{2}/, label: 'hex escape sequences in strings' },
  { pattern: /importlib/, label: 'dynamic import via importlib' },
  { pattern: /__import__\s*\(/, label: '__import__() dynamic import' },
];

/**
 * SIMULATED Model B code analyzer.
 * Score is high when AST fired (corroborating evidence) PLUS extra bump for
 * obfuscation markers, even when AST did not fire.
 * @param {string} code
 * @param {boolean} astFired
 * @returns {{ score: number, evidence: string[] }}
 */
function runModelBCode(code, astFired) {
  const evidence = [];
  let score = astFired ? 0.65 : 0.0; // Corroboration base

  for (const pat of OBFUSCATION_PATTERNS) {
    if (pat.pattern.test(code)) {
      evidence.push(pat.label);
      score = Math.min(1.0, score + 0.18);
    }
  }

  if (astFired && evidence.length > 0) {
    evidence.unshift('AST_TAINT corroborated: obfuscation techniques confirm intentional evasion');
    score = Math.min(1.0, score + 0.1);
  }

  if (!astFired && evidence.length === 0) {
    score = 0.0; // Clean bill of health from this model too
  }

  return { score: parseFloat(score.toFixed(3)), evidence };
}

// ─── Analyzer 2b: Model B Code — REAL model via the scan service ──────────────
// When MODEL_B_URL is set (e.g. http://127.0.0.1:8765, started with
// `python model_b_service/serve.py`), the trained Model B v8 classifier
// (UniXcoder + LoRA; command injection, path traversal, SSRF, code injection,
// SQL injection, unsafe deserialization) scores every function in the tools'
// source code (or, for older rows without source, the code blocks in the
// description) and, when github_url is a real public repo, the repo's source.
// Fail-closed: if the service is configured but unreachable, the result is
// REVIEW, never a silent PASS.

const MODEL_B_URL = process.env.MODEL_B_URL || '';
const MODEL_B_TIMEOUT_MS = Number(process.env.MODEL_B_TIMEOUT_MS || 600000);
const SOURCE_EXT = { python: '.py', typescript: '.ts', javascript: '.js' };

/**
 * @param {object} content
 * @returns {Promise<{ ok: boolean, findings?: object[], nFunctions?: number, notes: string[], modelHash: string|null, error?: string }>}
 */
async function runModelBService(content) {
  const files = (content.tools || [])
    .filter(t => t && t.source_code)
    .map((t, i) => ({
      path: `tools/${i}_${String(t.name || 'tool').replace(/[^\w.-]/g, '_')}${SOURCE_EXT[t.source_language] || '.py'}`,
      content: String(t.source_code),
    }));
  const body = { github_url: content.github_url || undefined };
  if (files.length > 0) body.files = files;
  else body.markdown = content.long_description || '';
  try {
    const res = await fetch(`${MODEL_B_URL.replace(/\/$/, '')}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(MODEL_B_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const r = await res.json();
    const notes = (r.sources || []).filter(s => s.startsWith('github unavailable')).map(s => `note: ${s}`);
    return { ok: true, findings: r.findings || [], nFunctions: r.n_functions, notes, modelHash: r.model_hash };
  } catch (e) {
    return { ok: false, error: e.message, notes: [], modelHash: null };
  }
}

/**
 * Turn Model B's per-function findings into the analyzer score, using the AST
 * taint hits as corroboration (ruleset.modelBPolicy).
 *
 * Model B reads one function at a time and cannot see whether tool input
 * reaches the risky call, so on its own it may send a server to REVIEW but
 * never FAIL it. A finding keeps its full score (and can FAIL) only when the
 * AST analyzer reports a medium/high flow of the matching category in the
 * same function.
 *
 * @param {object} svc - runModelBService() result
 * @param {object} astResult - runAstTaint() result
 * @returns {{ score: number, threat: string, evidence: string[], corroborated: number }}
 */
function fuseModelB(svc, astResult) {
  const policy = RULESET.modelBPolicy;
  const { fail, review } = RULESET.thresholds;
  if (!svc.ok) {
    return {
      score: review,
      threat: 'scanner_unavailable',
      evidence: [`Model B service unavailable (${svc.error}); manual review required`],
      corroborated: 0,
    };
  }
  const hits = astResult.engine === 'ast-taint' ? (astResult.hits || []) : [];
  const confirms = (func, cls) => hits.some(h => h.tool === func
    && policy.astCategoryToClass[h.category] === cls
    && policy.corroboratingSeverities.includes(String(h.severity).toLowerCase()));

  let best = { score: 0, threat: 'none' };
  const lines = [];
  let corroborated = 0;
  for (const f of svc.findings) {
    for (const [cls, s] of Object.entries(f.calibrated || {})) {
      if (s < review) continue;
      const ok = confirms(f.func_name, cls);
      const eff = ok ? s : (s >= fail ? policy.uncorroboratedFailScore : policy.uncorroboratedReviewScore);
      const threat = policy.classThreat[cls] || cls;
      if (ok) corroborated += 1;
      lines.push({
        eff,
        text: `${threat} in ${f.func_name}() at ${f.file}:${f.start_line} — model ${s.toFixed(2)}`
          + (ok ? ' [corroborated by AST taint flow → full score]'
            : s >= fail ? ' [no AST taint flow in this function → review]' : ' [below fail, no AST flow → evidence only]'),
      });
      if (eff > best.score) best = { score: eff, threat };
    }
  }
  lines.sort((a, b) => b.eff - a.eff);
  const evidence = [
    `engine: Model B v8 (REAL, ${svc.nFunctions} functions scanned, model ${String(svc.modelHash).slice(0, 12)}…)`,
    ...(lines.length > 0 ? lines.slice(0, 10).map(l => l.text) : ['No vulnerable code patterns detected']),
    ...svc.notes,
  ];
  return { score: parseFloat(best.score.toFixed(3)), threat: best.threat, evidence, corroborated };
}

// ─── Analyzer 3: Model A Text (tool poisoning + PMA) ──────────────────────────
// SIMULATED (POC): In production this is a fine-tuned text LLM (Model A) that
// detects injected natural-language directives in tool descriptions that could
// manipulate an AI agent's behavior (tool poisoning) or engage in PMA
// (Prompt Manipulation Attacks).

const POISON_PATTERNS = [
  { pattern: /ignore\s+(?:previous|above|prior|all)\s+(?:instructions?|rules?|context)/i, label: 'jailbreak directive: "ignore previous instructions"', threat: 'tool_poisoning' },
  { pattern: /do\s+not\s+(?:tell|inform|mention|show|disclose)\s+the\s+(?:user|human|operator)/i, label: 'concealment directive: "do not tell the user"', threat: 'tool_poisoning' },
  { pattern: /system\s*:/i, label: 'hidden system: prefix in tool description', threat: 'tool_poisoning' },
  { pattern: /\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>/i, label: 'embedded LLM control tokens in description', threat: 'tool_poisoning' },
  { pattern: /you\s+(?:must|should|shall|will)\s+always\s+(?:use|call|invoke)\s+this/i, label: 'imperative agent directive in description', threat: 'tool_poisoning' },
  { pattern: /without\s+asking\s+(?:the\s+)?user/i, label: 'covert-action directive: "without asking the user"', threat: 'tool_poisoning' },
  { pattern: /\bsilently\b|\bcovertly\b|\bwithout\s+notif/i, label: 'covert execution language', threat: 'tool_poisoning' },
];

const PMA_PATTERNS = [
  { pattern: /\balways\s+use\s+this\s+(?:tool|server|integration)\b/i, label: 'PMA superlative: "always use this tool"', threat: 'pma' },
  { pattern: /\bmost\s+(?:secure|reliable|trusted|advanced|official)\b/i, label: 'PMA superlative: false authority claim', threat: 'pma' },
  { pattern: /\bofficial\s+(?:tool|server|integration|mcp)\b/i, label: 'PMA false authority: "official tool"', threat: 'pma' },
  { pattern: /\bpreferred\s+(?:by|for|tool|method)\b/i, label: 'PMA nudge: "preferred by"', threat: 'pma' },
  { pattern: /\bonly\s+(?:way|method|option|tool)\b/i, label: 'PMA exclusivity: "only way/method"', threat: 'pma' },
  { pattern: /\btrusted\s+by\s+(?:millions|thousands|experts)\b/i, label: 'PMA social-proof fabrication', threat: 'pma' },
  { pattern: /\bguaranteed\b|\bzero\s+(?:risk|false)\b/i, label: 'PMA false guarantee language', threat: 'pma' },
];

/**
 * SIMULATED Model A text analyzer.
 * @param {string} description - tool or server description text
 * @returns {{ score: number, evidence: string[], threats: string[] }}
 */
function runModelAText(description) {
  const evidence = [];
  const threats = new Set();
  let score = 0;

  for (const pat of POISON_PATTERNS) {
    if (pat.pattern.test(description)) {
      evidence.push(pat.label);
      threats.add(pat.threat);
      score = Math.min(1.0, score + 0.40);
    }
  }

  for (const pat of PMA_PATTERNS) {
    if (pat.pattern.test(description)) {
      evidence.push(pat.label);
      threats.add(pat.threat);
      score = Math.min(1.0, score + 0.20);
    }
  }

  return {
    score: parseFloat(score.toFixed(3)),
    evidence,
    threats: [...threats],
  };
}

// ─── Policy Engine ────────────────────────────────────────────────────────────
// PURE AND DETERMINISTIC. Same inputs always produce the same verdict.
// This is NOT simulated — it reflects the production policy intent exactly.

/**
 * Decide the final verdict from analyzer results.
 * Rules (from ruleset.json):
 *   - AST_TAINT hard-fired (score >= 0.6) → FAIL (regardless of others)
 *   - Any score >= thresholds.fail → FAIL
 *   - Any score >= thresholds.review → REVIEW
 *   - Otherwise → PASS
 *
 * @param {Array<{analyzer, score, evidence}>} results
 * @returns {'PASS'|'REVIEW'|'FAIL'}
 */
function decideVerdict(results) {
  const { thresholds, astHardFail } = RULESET;

  for (const r of results) {
    if (astHardFail && r.analyzer === 'AST_TAINT' && r.score >= 0.6) {
      return 'FAIL';
    }
  }

  let maxScore = 0;
  for (const r of results) {
    maxScore = Math.max(maxScore, r.score);
  }

  if (maxScore >= thresholds.fail) return 'FAIL';
  if (maxScore >= thresholds.review) return 'REVIEW';
  return 'PASS';
}

// ─── Simulated commit SHA ─────────────────────────────────────────────────────

/**
 * Generate a deterministic simulated 40-hex "commit SHA" for a server version.
 * In production this would be the actual git commit SHA pinned at scan time.
 * @param {string} serverId
 * @param {number} version
 * @param {string} fingerprint
 * @returns {string}
 */
function simulateCommitSha(serverId, version, fingerprint) {
  // Deterministic: same inputs → same "commit sha"
  return mcscrpyto.sha256hex(`commit:${serverId}:v${version}:${fingerprint}`).slice(0, 40);
}

// ─── Main Entry Point ─────────────────────────────────────────────────────────

/**
 * Run the full simulated scan pipeline on a server's content.
 * This is DETERMINISTIC — same input always produces the same ScanRecord.
 *
 * @param {object} content - { serverId, name, description, long_description, github_url, tools }
 * @param {number} [version=1]
 * @returns {ScanRecord}
 */
async function simulateScan(content, version = 1, onStage = null) {
  // Stage notifications are for the live UI only. Durations are deliberately
  // NOT written into the ScanRecord — the signed artifact must stay
  // byte-identical across runs, and a timestamp would destroy that.
  const stage = async (name, status, detail) => {
    // Reserved keys go LAST so a detail field can never clobber them.
    if (onStage) await onStage({ ...(detail || {}), stage: name, status });
  };

  const timed = async (name, run, describe) => {
    await stage(name, 'start');
    const startedAt = Date.now();
    const value = await run();
    await stage(name, 'done', { ms: Date.now() - startedAt, ...(describe ? describe(value) : {}) });
    return value;
  };

  await stage('parse', 'start');

  // ── Code view ──────────────────────────────────────────────────────────────
  // Prefer the real implementation source stored per tool. Only fall back to
  // scraping markdown when a server predates the source_code column.
  const toolSources = (content.tools || [])
    .map(t => (t && t.source_code ? String(t.source_code).trim() : ''))
    .filter(Boolean);

  const usingRealSource = toolSources.length > 0;
  const codeText = usingRealSource
    ? toolSources.join('\n\n\n')
    : [
        content.long_description || '',
        (content.tools || []).map(t => t.description || '').join('\n'),
      ].join('\n');

  // ── Text view (what Model A reads) ─────────────────────────────────────────
  const descriptionText = [
    content.description || '',
    content.name || '',
    (content.tools || []).map(t => `${t.name}: ${t.description || ''}`).join('\n'),
  ].join('\n');

  await stage('parse', 'done', {
    codeChars: codeText.length,
    textChars: descriptionText.length,
    codeOrigin: usingRealSource ? 'tool_source' : 'markdown',
    toolCount: (content.tools || []).length,
    sourcedTools: toolSources.length,
  });

  // ── Run analyzers (Detection Pipeline runs FIRST) ───────────────────────────
  const astResult = await timed('ast_taint', () => runAstTaint(codeText),
    v => ({ score: v.score, engine: v.engine, findings: (v.hits || []).length }));
  let realModelB = null;
  const modelBResult = await timed('model_b', async () => {
    if (!MODEL_B_URL) return runModelBCode(codeText, astResult.fired);
    realModelB = await runModelBService(content);
    return fuseModelB(realModelB, astResult);
  }, v => ({ score: v.score, engine: realModelB ? 'model-b-v8' : 'simulated' }));
  const modelAResult = await timed('model_a', () => runModelAText(descriptionText),
    v => ({ score: v.score }));

  const analyzers = [
    {
      analyzer: 'AST_TAINT',
      // Keyed off the score, not evidence length: evidence now always carries
      // a leading "engine:" line, so counting it would flag every scan.
      threat: astResult.score > 0 ? 'command_injection' : 'none',
      score: astResult.score,
      engine: astResult.engine,
      evidence: astResult.evidence,
    },
    {
      analyzer: 'MODEL_B_CODE',
      threat: realModelB ? (modelBResult.score >= RULESET.thresholds.review ? modelBResult.threat : 'none')
        : (modelBResult.score >= RULESET.thresholds.review ? 'command_injection' : 'none'),
      score: modelBResult.score,
      engine: realModelB ? 'model-b-v8' : 'simulated',
      evidence: modelBResult.evidence.length > 0 ? modelBResult.evidence : ['No obfuscation or injection patterns detected in code'],
    },
    {
      analyzer: 'MODEL_A_TEXT',
      threat: modelAResult.threats.length > 0 ? modelAResult.threats[0] : 'none',
      score: modelAResult.score,
      evidence: modelAResult.evidence.length > 0 ? modelAResult.evidence : ['No tool-poisoning or PMA phrases detected in descriptions'],
    },
  ];

  // ── Policy Engine: Evaluate detection findings ─────────────────────────────
  const verdict = await timed('policy', () => decideVerdict(analyzers), v => ({ verdict: v }));

  // ── Conditional Hash Generation: ONLY when detection is CLEAR (PASS) ───────
  await stage('fingerprint', 'start', { verdict });
  let snapshot;
  let hashesGenerated = false;

  if (verdict === 'PASS') {
    // Detection is clear — generate canonical content fingerprint & commit SHA
    const contentFingerprint = mcscrpyto.fingerprintContent({
      name: content.name || '',
      description: content.description || '',
      long_description: content.long_description || '',
      github_url: content.github_url || '',
      tools: (content.tools || []).map(t => ({ name: t.name, description: t.description })),
    });

    const commitSha = simulateCommitSha(content.serverId, version, contentFingerprint);
    hashesGenerated = true;

    snapshot = {
      serverId: content.serverId,
      version,
      repoRef: content.github_url || `internal://server/${content.serverId}`,
      commitSha,
      contentFingerprint,
      hashesGenerated: true,
      blockchainEligible: true,
      scannedAt: new Date().toISOString(),
    };
  } else {
    // Detection NOT clear — hashes are NOT generated and blockchain storage is blocked
    snapshot = {
      serverId: content.serverId,
      version,
      repoRef: content.github_url || `internal://server/${content.serverId}`,
      commitSha: null,
      contentFingerprint: null,
      hashesGenerated: false,
      blockchainEligible: false,
      blockedReason: verdict === 'FAIL'
        ? 'Critical security threats detected during pipeline. Hashes withheld; storage in blockchain blocked.'
        : 'Suspicious patterns flagged for review. Hashes withheld until manual clearance.',
      scannedAt: new Date().toISOString(),
    };
  }

  await stage('fingerprint', 'done', {
    hashesGenerated,
    contentFingerprint: snapshot.contentFingerprint,
    blockedReason: snapshot.blockedReason || null,
  });

  // When the real analyzer ran, pin the SHA-256 of its detection config rather
  // than the placeholder. config.py is what decides whether something is a
  // sink, so that hash is what actually makes this verdict reproducible.
  const modelVersionHashes = { ...RULESET.modelVersionHashes };
  if (astResult.engine === 'ast-taint' && astResult.configHash) {
    modelVersionHashes.AST_TAINT = astResult.configHash;
  }
  if (realModelB && realModelB.modelHash) {
    modelVersionHashes.MODEL_B_CODE = realModelB.modelHash;
  }

  return {
    snapshot,
    analyzers,
    verdict,
    hashesGenerated,
    policyVersion: RULESET.policyVersion,
    rulesetHash: RULESET_HASH,
    modelVersionHashes,
  };
}

module.exports = {
  simulateScan,
  runAstTaint,
  runAstTaintHeuristic,
  runModelBCode,
  runModelBService,
  fuseModelB,
  runModelAText,
  decideVerdict,
  RULESET,
  RULESET_HASH,
};
