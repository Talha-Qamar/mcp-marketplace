/**
 * MCP Secure — Policy engine (spec §7)
 * =====================================
 * decide(slotResults, bundle, ruleset) → PolicyResult
 *
 * Pure and deterministic: no I/O, no clock, no randomness. Rule TYPES are
 * implemented here; rule INSTANCES (which slot, which thresholds) live in
 * ruleset.json, whose hash is pinned in every scan record. Tuning a rule is a
 * ruleset change, not a code change.
 */

const RANK = { PASS: 0, REVIEW: 1, FAIL: 2 };
const OK_STATUSES = new Set(['ok', 'partial']);

function maxVerdict(a, b) {
  return RANK[b] > RANK[a] ? b : a;
}

function spansOverlap(a, b) {
  return a && b && a.start_line <= b.end_line && b.start_line <= a.end_line;
}

/** Does `finding` have a corroborating finding (same file, overlapping function, same threat)? */
function corroborated(finding, candidates, severities) {
  const loc = finding.location || {};
  return candidates.find(c => {
    const cl = c.location || {};
    return c.threat === finding.threat
      && severities.includes(c.severity)
      && cl.file && cl.file === loc.file
      && spansOverlap(cl.function, loc.function);
  });
}

/** Last segment of an analyzer function name: `Cls.run` → `run`, `tool:ui_tap` → `ui_tap`. */
function bareName(fn) {
  const parts = String((fn && fn.name) || '').split(/[.:]/);
  return parts[parts.length - 1];
}

/**
 * Is the finding on a tool's input path? 'tool_handler': inside a discovered
 * tool handler (tool arguments are attacker input by definition).
 * 'handler_callee': in a function a tool handler calls directly (by name, in
 * a file tool code reaches). Returns the matching kind or null.
 */
function onToolPath(finding, bundle, kinds) {
  const loc = finding.location || {};
  if (kinds.includes('tool_handler') && loc.tool_id) return 'tool_handler';
  if (kinds.includes('handler_callee') && loc.function) {
    const file = (bundle.files || []).find(f => f.path === loc.file);
    if (!file || file.tool_reachable !== true) return null;
    const name = bareName(loc.function);
    if (name && (bundle.tools || []).some(t => (t.calls || []).includes(name))) return 'handler_callee';
  }
  return null;
}

function bySlot(slotResults) {
  const m = new Map();
  for (const s of slotResults) m.set(s.slot, s);
  return m;
}

function findingsOf(slot) {
  return slot && OK_STATUSES.has(slot.result.status) ? (slot.result.findings || []) : [];
}

const RULE_TYPES = {
  require_analyzers(rule, ctx) {
    const missing = ctx.slots.filter(s => s.required && !OK_STATUSES.has(s.result.status) && s.result.status !== 'not_applicable');
    if (missing.length === 0) return null;
    return {
      verdict: rule.verdict || 'REVIEW',
      message: `required analyzer(s) did not run: ${missing.map(s => `${s.slot} (${s.result.status}${s.result.error ? `: ${s.result.error}` : ''})`).join(', ')}`,
    };
  },

  require_pinned_artifacts(rule, ctx) {
    const pins = ctx.ruleset.analyzerPins || {};
    const off = ctx.slots.filter(s => pins[s.slot] && s.result.analyzer && s.result.analyzer.artifact_hash
      && OK_STATUSES.has(s.result.status) && s.result.analyzer.artifact_hash !== pins[s.slot]);
    if (off.length === 0) return null;
    return {
      verdict: rule.verdict || 'REVIEW',
      message: `analyzer version not pinned by this ruleset: ${off.map(s => `${s.slot} reports ${String(s.result.analyzer.artifact_hash).slice(0, 19)}…, pinned ${String(pins[s.slot]).slice(0, 19)}…`).join('; ')}`,
    };
  },

  require_code_coverage(rule, ctx) {
    // A code analyzer that ran on the code counts, even when it found nothing
    // to score (e.g. only one-line handlers). not_applicable/error do not.
    const code = ctx.slots.filter(s => s.kind === 'code');
    const covered = code.some(s => OK_STATUSES.has(s.result.status));
    if (covered) return null;
    const why = ctx.bundle.files.length === 0
      ? 'no Python/TypeScript/JavaScript source to analyse'
      : 'no code analyzer analysed the source';
    return { verdict: rule.verdict || 'REVIEW', message: `insufficient code coverage: ${why}` };
  },

  require_complete_source(rule, ctx) {
    const skipped = ctx.bundle.coverage.skipped_code || [];
    if (skipped.length === 0) return null;
    return {
      verdict: rule.verdict || 'REVIEW',
      message: `${skipped.length} code file(s) were not analysed (${skipped.slice(0, 3).map(f => `${f.path}: ${f.reason}`).join('; ')}${skipped.length > 3 ? '; …' : ''})`,
    };
  },

  require_resolved_descriptions(rule, ctx) {
    const unresolved = ctx.bundle.coverage.unresolved_descriptions || [];
    if (unresolved.length === 0) return null;
    return {
      verdict: rule.verdict || 'REVIEW',
      message: `${unresolved.length} tool description(s) are built at runtime and could not be checked: ${unresolved.slice(0, 3).join(', ')}`,
    };
  },

  require_tool_discovery(rule, ctx) {
    if (ctx.bundle.coverage.tool_discovery !== 'none') return null;
    return { verdict: rule.verdict || 'REVIEW', message: 'no MCP tools were found in the source' };
  },

  hard_fail(rule, ctx) {
    const hits = findingsOf(ctx.byId.get(rule.slot)).filter(f => rule.severities.includes(f.severity));
    if (hits.length === 0) return null;
    return {
      verdict: 'FAIL',
      message: `${hits.length} ${rule.severities.join('/')} finding(s) from ${rule.slot}`,
      finding_ids: hits.map(f => f.finding_id),
    };
  },

  cap_outside_reachable(rule, ctx) {
    // Only meaningful when ingestion anchored reachability on discovered tools.
    const reach = new Map((ctx.bundle.files || []).map(f => [f.path, f.tool_reachable]));
    const capped = [];
    for (const eff of ctx.effective) {
      if (!rule.slots.includes(eff.slot)) continue;
      if (reach.get((eff.finding.location || {}).file) !== false) continue;
      if (eff.effective_score > rule.cap) {
        eff.effective_score = rule.cap;
        eff.rule = rule.id;
        capped.push(eff.finding_id);
      }
    }
    if (capped.length === 0) return null;
    return { verdict: null, message: `${capped.length} finding(s) in code no MCP tool reaches counted as evidence only`, finding_ids: capped };
  },

  cap_unless_corroborated(rule, ctx) {
    const support = (rule.corroborating_slots || [rule.corroborating_slot]).flatMap(id => findingsOf(ctx.byId.get(id)));
    const trusted = rule.trusted_locations || [];
    const capped = [];
    for (const eff of ctx.effective) {
      if (eff.slot !== rule.slot) continue;
      if (eff.rule) continue; // already capped by an earlier rule
      const match = corroborated(eff.finding, support, rule.corroborating_severities);
      if (match) {
        eff.corroborated_by = match.finding_id;
        continue;
      }
      const path = eff.raw_score >= (rule.trusted_min_score ?? 0)
        && !(rule.trusted_exclude_threats || []).includes(eff.threat)
        && onToolPath(eff.finding, ctx.bundle, trusted);
      if (path) {
        eff.corroborated_by = path;
        continue;
      }
      const cap = rule.caps.find(c => eff.raw_score >= c.min_score);
      if (cap && eff.effective_score > cap.cap) {
        eff.effective_score = cap.cap;
        eff.rule = rule.id;
        capped.push(eff.finding_id);
      }
    }
    if (capped.length === 0) return null;
    return { verdict: null, message: `${capped.length} ${rule.slot} finding(s) capped: no corroborating ${rule.corroborating_slot} flow`, finding_ids: capped };
  },

  threshold(rule, ctx) {
    const { fail, review } = ctx.ruleset.thresholds;
    let top = null;
    for (const eff of ctx.effective) if (!top || eff.effective_score > top.effective_score) top = eff;
    if (!top || top.effective_score < review) return null;
    const verdict = top.effective_score >= fail ? 'FAIL' : 'REVIEW';
    const over = ctx.effective.filter(e => e.effective_score >= review);
    return {
      verdict,
      message: `highest effective score ${top.effective_score.toFixed(2)} (${top.threat}, ${top.slot}) ≥ ${verdict === 'FAIL' ? 'fail' : 'review'} threshold`,
      finding_ids: over.map(e => e.finding_id),
    };
  },
};

/**
 * @param {Array<{slot, kind, required, result}>} slotResults  analyze-stage results
 * @param {object} bundle   AnalysisBundle
 * @param {object} ruleset  parsed ruleset.json
 */
function decide(slotResults, bundle, ruleset) {
  const ctx = {
    slots: slotResults,
    byId: bySlot(slotResults),
    bundle,
    ruleset,
    effective: [],
  };
  for (const s of slotResults) {
    for (const f of findingsOf(s)) {
      ctx.effective.push({
        slot: s.slot,
        finding_id: f.finding_id,
        threat: f.threat,
        severity: f.severity,
        raw_score: f.score,
        effective_score: f.score,
        rule: null,
        finding: f,
      });
    }
  }

  let verdict = 'PASS';
  const reasons = [];
  for (const rule of ruleset.rules) {
    const impl = RULE_TYPES[rule.type];
    if (!impl) throw new Error(`policy: unknown rule type '${rule.type}' (${rule.id})`);
    const out = impl(rule, ctx);
    if (!out) continue;
    reasons.push({ rule: rule.id, verdict: out.verdict, message: out.message, finding_ids: out.finding_ids || [] });
    if (out.verdict) verdict = maxVerdict(verdict, out.verdict);
  }

  const effective = ctx.effective
    .map(({ finding, ...e }) => e)
    .sort((a, b) => b.effective_score - a.effective_score || (a.finding_id < b.finding_id ? -1 : 1));
  const maxScore = effective.length ? effective[0].effective_score : 0;
  return {
    verdict,
    reasons,
    max_effective_score: maxScore,
    effective_findings: effective,
  };
}

module.exports = { decide, RULE_TYPES };
