/**
 * Built-in ingestion checks (deterministic):
 *   • declared tools vs tools found in the code (spec §4.4): a listing that
 *     shows different tools from the ones the server ships;
 *   • hidden characters in descriptions: zero-width, bidirectional-override
 *     and Unicode tag characters render as nothing to a human reviewer but are
 *     read by the model, which is how instructions get smuggled into a
 *     description.
 */

const { canonicalDigest, sha256Hex } = require('../../canonical');

const ID = 'ingest_checks';
const VERSION = '1.1.0';

// zero-width, bidi embedding/override/isolate, word joiner, BOM, Unicode tags
const HIDDEN_RE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]|\uDB40[\uDC00-\uDC7F]/g;
const ARTIFACT_HASH = 'sha256:' + sha256Hex(`${ID}@${VERSION}`);

function identity() {
  return { id: ID, version: VERSION, artifact_hash: ARTIFACT_HASH, engine: 'static' };
}

function health() {
  return {
    ...identity(),
    display_name: 'Declared vs discovered tools',
    description: 'Declared vs discovered tools, and hidden characters in descriptions',
    consumes: ['server', 'tools', 'declared_tools'],
    languages: ['*'],
    threats: ['metadata_mismatch', 'tool_poisoning'],
    contract_version: '1',
  };
}

function hiddenCharFindings(bundle) {
  const findings = [];
  const texts = [{ where: 'server listing', tool: null, text: `${bundle.server.name}\n${bundle.server.description}` }];
  for (const t of bundle.tools) {
    const props = (t.input_schema && t.input_schema.properties) || {};
    const paramText = Object.keys(props).sort().map(k => (props[k] && props[k].description) || '').join('\n');
    texts.push({ where: `tool '${t.name}'`, tool: t, text: `${t.name}\n${t.description}\n${paramText}` });
  }
  for (const u of texts) {
    const hits = u.text.match(HIDDEN_RE);
    if (!hits) continue;
    const codepoints = [...new Set(hits.map(h => 'U+' + h.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')))];
    findings.push({
      finding_id: canonicalDigest([ID, 'hidden_chars', u.tool ? u.tool.tool_id : 'server', codepoints]),
      threat: 'tool_poisoning', cwe: null, score: 0.55, severity: 'medium',
      location: u.tool
        ? { file: u.tool.file, line: u.tool.handler.start_line, function: { ...u.tool.handler }, tool_id: u.tool.tool_id }
        : { file: null, line: null, function: null, tool_id: null },
      summary: `${hits.length} hidden character(s) in ${u.where} (${codepoints.join(', ')}): text a reviewer cannot see but the model reads`,
      details: { kind: 'hidden_characters', codepoints, count: hits.length },
    });
  }
  return findings;
}

function mismatchFindings(bundle) {
  const declared = bundle.declared_tools || [];
  if (declared.length === 0) return [];
  const found = new Set(bundle.tools.map(t => t.name));
  const want = new Set(declared.map(t => t.name));
  const findings = [];
  for (const name of [...want].filter(n => !found.has(n)).sort()) {
    findings.push({
      finding_id: canonicalDigest([ID, 'declared_missing', name]),
      threat: 'metadata_mismatch', cwe: null, score: 0.55, severity: 'medium',
      location: { file: null, line: null, function: null, tool_id: null },
      summary: `declared tool '${name}' was not found in the code`,
      details: { kind: 'declared_not_found', tool: name },
    });
  }
  for (const t of bundle.tools.filter(x => !want.has(x.name))) {
    findings.push({
      finding_id: canonicalDigest([ID, 'undeclared', t.tool_id]),
      threat: 'metadata_mismatch', cwe: null, score: 0.55, severity: 'medium',
      location: { file: t.file, line: t.handler.start_line, function: { ...t.handler }, tool_id: t.tool_id },
      summary: `tool '${t.name}' exists in the code but is not declared in the listing`,
      details: { kind: 'undeclared_tool', tool: t.name },
    });
  }
  return findings;
}

function analyze(bundle) {
  const findings = [...mismatchFindings(bundle), ...hiddenCharFindings(bundle)];
  const key = f => [f.location.file || '', f.location.line || 0, f.threat, f.finding_id];
  findings.sort((a, b) => {
    const ka = key(a), kb = key(b);
    for (let i = 0; i < ka.length; i++) if (ka[i] !== kb[i]) return ka[i] < kb[i] ? -1 : 1;
    return 0;
  });
  const units = 1 + bundle.tools.length + (bundle.declared_tools || []).length;
  return {
    analyzer: identity(), status: 'ok',
    coverage: { units_total: units, units_analyzed: units, languages: ['text'], notes: (bundle.declared_tools || []).length ? [] : ['no declared tools: mismatch check skipped'] },
    findings,
  };
}

module.exports = { id: ID, health, analyze };
