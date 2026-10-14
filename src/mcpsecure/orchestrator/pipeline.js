/**
 * MCP Secure — Orchestrator (spec §3, §5)
 * ========================================
 * runPipeline({ source, listing, declaredTools }, { onStage }) →
 *   { bundle, slots, policy, triage }
 *
 *   1 INGEST   source → AnalysisBundle (pinned commit, code-covering fingerprint)
 *   2 ANALYZE  every analyze-stage registry slot, in parallel, same bundle
 *   3 POLICY   pure function over the contract findings (ruleset.json)
 *   4 TRIAGE   REVIEW only: Model C's advisory recommendation (never changes the verdict, D2)
 *
 * Headless: no Express, no marketplace database. The marketplace, the
 * evaluation CLI and (later) the external MCP Secure server all call this.
 * Stage events carry measured durations for the live UI; durations never go
 * into anything that is hashed or signed.
 */

const fs = require('fs');
const path = require('path');
const { ingest, describeBundle } = require('../ingest');
const { loadRegistry } = require('./registry');
const { runSlot } = require('./client');
const policy = require('../policy/engine');
const { sha256Hex } = require('../canonical');

const RULESET_PATH = path.join(__dirname, '..', 'ruleset.json');

function loadRuleset() {
  const text = fs.readFileSync(RULESET_PATH, 'utf8');
  return { ruleset: JSON.parse(text), hash: sha256Hex(text) };
}

function summarizeSlot(s) {
  const findings = s.result.findings || [];
  return {
    status: s.result.status,
    engine: (s.health && s.health.engine) || s.result.analyzer.engine,
    findings: findings.length,
    score: findings.reduce((m, f) => Math.max(m, f.score), 0),
    error: s.result.error,
  };
}

async function runPipeline(request, { onStage = null, registry = null, rulesetOverride = null } = {}) {
  const emit = async (stage, status, detail) => {
    if (onStage) await onStage({ ...(detail || {}), stage, status });
  };
  const timed = async (stage, fn, describe) => {
    await emit(stage, 'start');
    const t0 = Date.now();
    const value = await fn();
    await emit(stage, 'done', { ms: Date.now() - t0, ...(describe ? describe(value) : {}) });
    return value;
  };

  const slots = registry || loadRegistry();
  const { ruleset, hash: rulesetHash } = rulesetOverride || loadRuleset();

  // 1. Ingest
  const bundle = await timed('ingest', () => ingest(request), b => describeBundle(b));

  // 2. Analyze (parallel)
  const analyzeSlots = slots.filter(s => s.stage === 'analyze');
  const results = await Promise.all(analyzeSlots.map(slot =>
    timed(slot.id, () => runSlot(slot, bundle), summarizeSlot)));

  // 3. Policy
  const decision = await timed('policy', () => policy.decide(results, bundle, ruleset), d => ({ verdict: d.verdict }));

  // 4. Triage (advisory)
  let triage = null;
  const triageSlot = slots.find(s => s.stage === 'triage' && s.mode !== 'none' && (!s.when || s.when === decision.verdict));
  if (triageSlot) {
    triage = await timed('triage', () => runSlot(triageSlot, bundle, {
      verdict: decision.verdict,
      reasons: decision.reasons,
      findings: results.flatMap(r => (r.result.findings || []).map(f => ({ slot: r.slot, ...f }))),
    }), summarizeSlot);
  }

  return { bundle, slots: results, policy: decision, triage, ruleset, rulesetHash };
}

module.exports = { runPipeline, loadRuleset, RULESET_PATH };
