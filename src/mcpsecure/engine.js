/**
 * MCP Secure — Deterministic Scan Engine
 * =======================================
 * SIMULATED (POC): The three analyzer "models" are deterministic heuristics.
 * They produce the same output for the same input every time.
 * In production these would be fine-tuned ML models (LoRA adapters) running
 * offline inference. The policy engine logic is identical to production intent.
 *
 * simulateScan(content) → ScanRecord
 *
 * Heuristics are VISIBLE and TRANSPARENT — the UI shows exactly WHY
 * a verdict was reached via the evidence[] arrays.
 */

const mcscrpyto = require('./crypto');
const path = require('path');
const fs = require('fs');

// Load ruleset once at module init
const RULESET_PATH = path.join(__dirname, 'ruleset.json');
const RULESET = JSON.parse(fs.readFileSync(RULESET_PATH, 'utf8'));
const RULESET_HASH = mcscrpyto.sha256hex(fs.readFileSync(RULESET_PATH, 'utf8'));

// ─── Analyzer 1: AST Taint (command injection — hard signal) ──────────────────
// SIMULATED (POC): In production this runs a real AST parser (tree-sitter or
// python-ast) and performs inter-procedural taint tracking to check if
// attacker-controlled data reaches dangerous sinks.

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
 * SIMULATED AST taint analyzer.
 * Returns deterministic results based on string heuristics.
 * @param {string} code
 * @returns {{ score: number, evidence: string[], fired: boolean }}
 */
function runAstTaint(code) {
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
// SQL injection, unsafe deserialization) scores the code blocks in the server
// description and, when github_url is a real public repo, the repo's source.
// Fail-closed: if the service is configured but unreachable, the result is
// REVIEW, never a silent PASS.

const MODEL_B_URL = process.env.MODEL_B_URL || '';
const MODEL_B_TIMEOUT_MS = Number(process.env.MODEL_B_TIMEOUT_MS || 600000);

/**
 * @param {object} content
 * @returns {Promise<{ score: number, evidence: string[], threat: string, modelHash: string|null }>}
 */
async function runModelBService(content) {
  try {
    const res = await fetch(`${MODEL_B_URL.replace(/\/$/, '')}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ markdown: content.long_description || '', github_url: content.github_url || undefined }),
      signal: AbortSignal.timeout(MODEL_B_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const r = await res.json();
    const evidence = r.evidence.length > 0 ? [...r.evidence]
      : [`No vulnerable code patterns detected (${r.n_functions} functions scanned)`];
    for (const s of r.sources || []) {
      if (s.startsWith('github unavailable')) evidence.push(`note: ${s}`);
    }
    return { score: r.score, evidence, threat: r.threat, modelHash: r.model_hash };
  } catch (e) {
    return {
      score: RULESET.thresholds.review,
      evidence: [`Model B service unavailable (${e.message}); manual review required`],
      threat: 'scanner_unavailable',
      modelHash: null,
    };
  }
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
function simulateScan(content, version = 1) {
  return buildScanRecord(content, version, null);
}

/**
 * Scan with the real Model B when MODEL_B_URL is set; otherwise identical to simulateScan().
 * @param {object} content
 * @param {number} [version=1]
 * @returns {Promise<ScanRecord>}
 */
async function runScan(content, version = 1) {
  if (!MODEL_B_URL) return simulateScan(content, version);
  return buildScanRecord(content, version, await runModelBService(content));
}

function buildScanRecord(content, version, realModelB) {
  // Build the text corpus for analysis
  const codeText = [
    content.long_description || '',
    (content.tools || []).map(t => t.description || '').join('\n'),
  ].join('\n');

  const descriptionText = [
    content.description || '',
    content.name || '',
    (content.tools || []).map(t => `${t.name}: ${t.description || ''}`).join('\n'),
  ].join('\n');

  // ── Run analyzers (Detection Pipeline runs FIRST) ───────────────────────────
  const astResult = runAstTaint(codeText);
  const modelBResult = realModelB || runModelBCode(codeText, astResult.fired);
  const modelAResult = runModelAText(descriptionText);

  const analyzers = [
    {
      analyzer: 'AST_TAINT',
      threat: astResult.evidence.length > 0 ? 'command_injection' : 'none',
      score: astResult.score,
      evidence: astResult.evidence.length > 0 ? astResult.evidence : ['No tainted data flow to dangerous sinks detected'],
    },
    {
      analyzer: 'MODEL_B_CODE',
      threat: realModelB ? realModelB.threat
        : (modelBResult.score >= RULESET.thresholds.review ? 'command_injection' : 'none'),
      score: modelBResult.score,
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
  const verdict = decideVerdict(analyzers);

  // ── Conditional Hash Generation: ONLY when detection is CLEAR (PASS) ───────
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

  return {
    snapshot,
    analyzers,
    verdict,
    hashesGenerated,
    policyVersion: RULESET.policyVersion,
    rulesetHash: RULESET_HASH,
    modelVersionHashes: realModelB && realModelB.modelHash
      ? { ...RULESET.modelVersionHashes, MODEL_B_CODE: realModelB.modelHash }
      : RULESET.modelVersionHashes,
    modelBMode: realModelB ? 'model-b-v8' : 'simulated',
  };
}

module.exports = {
  simulateScan,
  runScan,
  runModelBService,
  runAstTaint,
  runModelBCode,
  runModelAText,
  decideVerdict,
  RULESET,
  RULESET_HASH,
};
