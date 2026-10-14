/**
 * Built-in stand-in for Model A (tool poisoning + preference manipulation).
 * ========================================================================
 * Same contract as a remote analyzer (spec §6), engine "heuristic", so the UI
 * labels it honestly. Used only while MODEL_A_URL is unset; Talha's trained
 * Model A replaces it by configuration, with no code change.
 *
 * One unit of text = the server listing, or one tool (name + description +
 * parameter descriptions). Score per unit: +0.40 per poisoning pattern, +0.20
 * per preference-manipulation pattern, capped at 1.0 (the POC's formula).
 */

const { canonicalDigest, sha256Hex } = require('../../canonical');

const VERSION = '1.0.0';
const ID = 'text_heuristic';

const POISON_PATTERNS = [
  { re: /ignore\s+(?:previous|above|prior|all)\s+(?:\w+\s+)?(?:instructions?|rules?|context|restrictions?)/i, label: 'jailbreak directive: "ignore previous instructions"' },
  { re: /do\s+not\s+(?:tell|inform|mention|show|disclose)\s+the\s+(?:user|human|operator)/i, label: 'concealment directive: "do not tell the user"' },
  { re: /(?:^|\s)system\s*:/i, label: 'hidden "system:" prefix in a description' },
  { re: /\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>/i, label: 'embedded LLM control tokens' },
  { re: /you\s+(?:must|should|shall|will)\s+always\s+(?:use|call|invoke)\s+this/i, label: 'imperative agent directive' },
  { re: /without\s+asking\s+(?:the\s+)?user/i, label: 'covert-action directive: "without asking the user"' },
  { re: /\bsilently\b|\bcovertly\b|\bwithout\s+notif/i, label: 'covert execution language' },
];

const PREFERENCE_PATTERNS = [
  { re: /\balways\s+use\s+this\s+(?:tool|server|integration)\b/i, label: 'superlative: "always use this tool"' },
  { re: /\bmost\s+(?:secure|reliable|trusted|advanced|official)\b/i, label: 'false authority: "most secure/trusted"' },
  { re: /\bofficial\s+(?:tool|server|integration|mcp)\b/i, label: 'false authority: "official tool"' },
  { re: /\bpreferred\s+(?:by|for|tool|method)\b/i, label: 'nudge: "preferred by"' },
  { re: /\bonly\s+(?:way|method|option|tool)\b/i, label: 'exclusivity: "only way/tool"' },
  { re: /\btrusted\s+by\s+(?:millions|thousands|experts)\b/i, label: 'social-proof fabrication' },
  { re: /\bguaranteed\b|\bzero\s+(?:risk|false)\b/i, label: 'false guarantee language' },
];

const ARTIFACT_HASH = 'sha256:' + sha256Hex(JSON.stringify({
  VERSION,
  poison: POISON_PATTERNS.map(p => p.re.source),
  preference: PREFERENCE_PATTERNS.map(p => p.re.source),
}));

function identity() {
  return { id: ID, version: VERSION, artifact_hash: ARTIFACT_HASH, engine: 'heuristic' };
}

function health() {
  return {
    ...identity(),
    display_name: 'Model A — text classifier (heuristic stand-in)',
    description: 'Regex stand-in for Model A until the trained model is served',
    consumes: ['server', 'tools'],
    languages: ['*'],
    threats: ['tool_poisoning', 'preference_manipulation'],
    contract_version: '1',
  };
}

function paramDescriptions(schema) {
  const props = (schema && schema.properties) || {};
  return Object.keys(props).sort().map(k => props[k] && props[k].description).filter(Boolean);
}

function scoreText(text) {
  const poison = POISON_PATTERNS.filter(p => p.re.test(text)).map(p => p.label);
  const preference = PREFERENCE_PATTERNS.filter(p => p.re.test(text)).map(p => p.label);
  const score = Math.min(1, poison.length * 0.4 + preference.length * 0.2);
  return { score: Number(score.toFixed(3)), poison, preference };
}

function severityOf(score) {
  return score >= 0.75 ? 'high' : score >= 0.4 ? 'medium' : 'low';
}

function analyze(bundle) {
  const units = [
    { kind: 'server', text: `${bundle.server.name}\n${bundle.server.description}`, tool: null },
    ...bundle.tools.map(t => ({
      kind: 'tool',
      text: [`${t.name}: ${t.description}`, ...paramDescriptions(t.input_schema)].join('\n'),
      tool: t,
    })),
  ];
  const findings = [];
  for (const u of units) {
    const { score, poison, preference } = scoreText(u.text);
    if (poison.length + preference.length === 0) continue;
    const threat = poison.length > 0 ? 'tool_poisoning' : 'preference_manipulation';
    const where = u.tool ? `tool '${u.tool.name}'` : 'server listing';
    findings.push({
      finding_id: canonicalDigest([ID, u.tool ? u.tool.tool_id : 'server', threat, [...poison, ...preference]]),
      threat,
      cwe: null,
      score,
      severity: severityOf(score),
      location: {
        file: u.tool ? u.tool.file : null,
        line: u.tool ? u.tool.handler.start_line : null,
        function: u.tool ? { ...u.tool.handler } : null,
        tool_id: u.tool ? u.tool.tool_id : null,
      },
      summary: `${threat.replace(/_/g, ' ')} language in ${where}: ${[...poison, ...preference].join('; ')}`,
      details: { poisoning: poison, preference_manipulation: preference },
    });
  }
  findings.sort((a, b) => {
    const ka = [a.location.file || '', a.location.line || 0, a.threat, a.finding_id];
    const kb = [b.location.file || '', b.location.line || 0, b.threat, b.finding_id];
    for (let i = 0; i < ka.length; i++) if (ka[i] !== kb[i]) return ka[i] < kb[i] ? -1 : 1;
    return 0;
  });
  return {
    analyzer: identity(),
    status: units.length > 0 ? 'ok' : 'not_applicable',
    coverage: { units_total: units.length, units_analyzed: units.length, languages: ['text'], notes: ['heuristic stand-in for Model A'] },
    findings,
  };
}

module.exports = { id: ID, health, analyze };
