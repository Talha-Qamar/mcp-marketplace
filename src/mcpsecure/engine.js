/**
 * MCP Secure — Scan engine
 * ========================
 * runScan(request, version, onStage) → ScanRecord
 *
 * Runs the orchestrator (ingest → analyzers → policy → triage) and shapes its
 * output into the ScanRecord that the service layer signs, logs and stores.
 *
 * Every analyzer is real or explicitly labelled: remote contract services (AST
 * taint, Model B), built-in stand-ins with engine "heuristic" (Model A until
 * the trained model is served), and slots that did not run are reported as
 * such — the policy then refuses to PASS (ruleset policy-v4).
 *
 * `analyzers` keeps the shape the existing UI renders (one card per slot);
 * `results`, `policy` and `ingest` carry the full contract data.
 */

const { runPipeline, loadRuleset } = require('./orchestrator/pipeline');

const THREAT_LABELS = require('../../contracts/threats.json').threats;

function slotDisplayName(s) {
  if (s.health && s.health.display_name) return s.health.display_name;
  return { ast_taint: 'AST taint analyzer', model_b: 'Model B — code classifier', model_a: 'Model A — text classifier', model_c: 'Model C — verification agent', ingest_checks: 'Declared vs discovered tools' }[s.slot] || s.slot;
}

function locationText(f) {
  const l = f.location || {};
  if (!l.file) return 'listing';
  return `${l.file}:${l.line}${l.function ? ` in ${l.function.name}()` : ''}`;
}

/** One UI card per analyze-stage slot, built from contract results and effective scores. */
function legacyAnalyzers(slots, decision) {
  const eff = new Map(decision.effective_findings.map(e => [e.finding_id, e]));
  return slots
    .filter(s => !(s.slot === 'ingest_checks' && s.result.status === 'not_applicable'))
    .map(s => {
      const r = s.result;
      const findings = r.findings || [];
      const engine = (s.health && s.health.engine) || (r.analyzer && r.analyzer.engine) || 'unknown';
      let score = 0;
      let threat = 'none';
      for (const f of findings) {
        const e = eff.get(f.finding_id);
        const value = e ? e.effective_score : f.score;
        if (value > score) { score = value; threat = f.threat; }
      }
      const identity = r.analyzer || {};
      const header = r.status === 'unavailable'
        ? `${s.slot}: not configured — analyzer did not run`
        : r.status === 'error'
          ? `${s.slot}: ERROR — ${r.error}`
          : `engine: ${identity.id} v${identity.version} (${engine}${s.fallbackUsed ? ', built-in stand-in' : ''}) · ${r.status} · ${(r.coverage || {}).units_analyzed || 0}/${(r.coverage || {}).units_total || 0} units · ${String(identity.artifact_hash || '').replace('sha256:', '').slice(0, 12)}…`;
      const lines = findings
        .map(f => {
          const e = eff.get(f.finding_id);
          const shown = e ? e.effective_score : f.score;
          const note = e && e.corroborated_by ? ' [corroborated by AST taint flow]'
            : e && e.rule ? ` [capped ${f.score.toFixed(2)} → ${shown.toFixed(2)}: no AST taint flow]` : '';
          return { shown, text: `${f.summary} — ${locationText(f)} — ${(shown * 100).toFixed(0)}%${note}` };
        })
        .sort((a, b) => b.shown - a.shown)
        .map(x => x.text);
      const empty = r.status === 'not_applicable'
        ? [`not applicable: ${((r.coverage || {}).notes || []).join('; ') || 'nothing this analyzer can read'}`]
        : (r.status === 'ok' || r.status === 'partial') && lines.length === 0 ? ['No findings'] : [];
      return {
        analyzer: s.slot,
        display_name: slotDisplayName(s),
        sublabel: ((s.health && s.health.threats) || []).map(t => (THREAT_LABELS[t] ? THREAT_LABELS[t].label : t).toLowerCase()).join(' · '),
        engine,
        status: r.status,
        required: s.required,
        fallbackUsed: !!s.fallbackUsed,
        threat,
        score: Number(score.toFixed(3)),
        evidence: [header, ...lines, ...empty, ...(((r.coverage || {}).notes) || []).map(n => `note: ${n}`)],
      };
    });
}

function compactResults(slots) {
  return slots.map(s => ({
    slot: s.slot,
    required: s.required,
    kind: s.kind,
    mode: s.mode,
    fallbackUsed: !!s.fallbackUsed,
    display_name: slotDisplayName(s),
    analyzer: s.result.analyzer,
    status: s.result.status,
    error: s.result.error || null,
    coverage: s.result.coverage,
    findings: s.result.findings || [],
  }));
}

/**
 * @param {object} request  { serverId, source, listing, declaredTools }
 * @param {number} [version=1]
 * @param {function} [onStage]
 * @returns {Promise<object>} ScanRecord
 */
async function runScan(request, version = 1, onStage = null) {
  const out = await runPipeline(request, { onStage });
  const { bundle, slots, policy: decision, triage } = out;
  const verdict = decision.verdict;

  const emit = async (stage, status, detail) => {
    if (onStage) await onStage({ ...(detail || {}), stage, status });
  };

  const repoRef = bundle.source.repo_url
    || (bundle.source.kind === 'local' ? `local://${request.listing && request.listing.slug ? request.listing.slug : request.serverId}` : `internal://server/${request.serverId}`);

  // Hashes are only surfaced for blockchain eligibility on PASS (unchanged
  // behaviour; the blockchain decisions are deferred, spec §8). The fingerprint
  // itself always exists and is kept in `subject` for the watcher.
  await emit('fingerprint', 'start', { verdict });
  const snapshot = {
    serverId: request.serverId,
    version,
    repoRef,
    commitSha: verdict === 'PASS' ? bundle.source.commit_sha : null,
    contentFingerprint: verdict === 'PASS' ? bundle.content_fingerprint : null,
    hashesGenerated: verdict === 'PASS',
    blockchainEligible: verdict === 'PASS',
    scannedAt: new Date().toISOString(),
  };
  if (verdict !== 'PASS') {
    snapshot.blockedReason = verdict === 'FAIL'
      ? 'Critical security threats detected during pipeline. Hashes withheld; storage in blockchain blocked.'
      : 'Flagged for review. Hashes withheld until manual clearance.';
  }
  await emit('fingerprint', 'done', {
    hashesGenerated: snapshot.hashesGenerated,
    contentFingerprint: snapshot.contentFingerprint,
    blockedReason: snapshot.blockedReason || null,
  });

  const modelVersionHashes = {};
  for (const s of slots) {
    if (s.result.analyzer && s.result.analyzer.artifact_hash) modelVersionHashes[s.slot] = s.result.analyzer.artifact_hash;
  }

  return {
    snapshot,
    subject: {
      source_kind: bundle.source.kind,
      repo_url: bundle.source.repo_url,
      ref: bundle.source.ref,
      subdir: bundle.source.subdir || null,
      commit_sha: bundle.source.commit_sha,
      content_fingerprint: bundle.content_fingerprint,
    },
    ingest: {
      files: bundle.files.map(f => ({ path: f.path, language: f.language, sha256: f.sha256, size: f.size })),
      tools: bundle.tools.map(t => ({ tool_id: t.tool_id, name: t.name, description: t.description, file: t.file, handler: t.handler, discovered_by: t.discovered_by, description_resolved: t.description_resolved })),
      tool_discovery: bundle.coverage.tool_discovery,
      notes: bundle.coverage.notes,
    },
    analyzers: legacyAnalyzers(slots, decision),
    results: compactResults(slots),
    policy: {
      verdict: decision.verdict,
      reasons: decision.reasons,
      max_effective_score: decision.max_effective_score,
      effective_findings: decision.effective_findings,
    },
    triage: triage ? {
      slot: triage.slot,
      analyzer: triage.result.analyzer,
      status: triage.result.status,
      error: triage.result.error || null,
      recommendation: triage.result.recommendation || null,
      advisory: true,
    } : null,
    verdict,
    hashesGenerated: snapshot.hashesGenerated,
    policyVersion: out.ruleset.policyVersion,
    rulesetHash: out.rulesetHash,
    modelVersionHashes,
  };
}

function currentRuleset() {
  return loadRuleset();
}

module.exports = { runScan, currentRuleset };
