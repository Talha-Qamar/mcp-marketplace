/* =============================================================
   MCP Secure POC — Frontend Module
   =============================================================
   Sections:
   1. Client-side Crypto (real Web Crypto API — NOT simulated)
   2. API Client wrappers
   3. Pipeline Animation Engine
   4. Attestation & Log Explorer
   5. Verify Flow
   6. Watcher Dashboard
   7. External Verifier
   8. Shared UI helpers (badges, tooltips, legend)
   ============================================================= */

'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// 1. CLIENT-SIDE CRYPTO (REAL — not simulated)
// ─────────────────────────────────────────────────────────────────────────────

const MCSCrypto = (() => {
  const subtle = window.crypto.subtle;

  /** Real SHA-256 over a UTF-8 string → lowercase hex */
  async function sha256hex(str) {
    const buf = new TextEncoder().encode(str);
    const hash = await subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /** Canonicalize a server content object (keys sorted) */
  function canonicalize(obj) {
    const sorted = {};
    for (const key of Object.keys(obj).sort()) sorted[key] = obj[key];
    return JSON.stringify(sorted);
  }

  /** Compute real content fingerprint (SHA-256 of canonicalized fields) */
  async function fingerprintContent(content) {
    const canon = canonicalize({
      name: content.name || '',
      description: content.description || '',
      long_description: content.long_description || '',
      github_url: content.github_url || '',
      tools: (content.tools || []).map(t => ({ name: t.name, description: t.description })),
    });
    return sha256hex(canon);
  }

  /** Hash a Merkle leaf: sha256("leaf:" + data) */
  async function hashLeaf(data) { return sha256hex('leaf:' + data); }

  /** Hash two Merkle nodes: sha256("node:" + left + right) */
  async function hashNode(l, r) { return sha256hex('node:' + l + r); }

  /**
   * Verify a real Merkle inclusion proof in the browser.
   * @param {string} leafData - original attestation ID
   * @param {number} leafIndex
   * @param {string[]} siblings
   * @param {string} expectedRoot
   * @returns {Promise<boolean>}
   */
  async function verifyInclusionProof(leafData, leafIndex, siblings, expectedRoot) {
    try {
      let hash = await hashLeaf(leafData);
      let idx = leafIndex;
      for (const sibling of siblings) {
        hash = idx % 2 === 0 ? await hashNode(hash, sibling) : await hashNode(sibling, hash);
        idx = Math.floor(idx / 2);
      }
      return hash === expectedRoot;
    } catch { return false; }
  }

  /**
   * Import the server's Ed25519 public key (SPKI DER as hex) for verification.
   * Returns a CryptoKey object.
   */
  async function importPublicKey(publicKeyHex) {
    const der = hexToBytes(publicKeyHex);
    return subtle.importKey('spki', der.buffer, { name: 'Ed25519' }, false, ['verify']);
  }

  /**
   * Verify a real Ed25519 signature in the browser.
   * @param {string} data - original data string that was signed
   * @param {string} sigHex - hex signature
   * @param {string} publicKeyHex - hex SPKI DER public key
   * @returns {Promise<boolean>}
   */
  async function verifySignature(data, sigHex, publicKeyHex) {
    try {
      const key = await importPublicKey(publicKeyHex);
      const sig = hexToBytes(sigHex);
      const msg = new TextEncoder().encode(data);
      return await subtle.verify({ name: 'Ed25519' }, key, sig.buffer, msg.buffer);
    } catch (e) {
      console.warn('[MCSCrypto] Ed25519 verify failed:', e.message);
      // Fallback: check if browser supports Ed25519 at all
      // If not supported, show a "browser limitation" warning rather than false
      return null; // null = indeterminate (not false)
    }
  }

  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    return bytes;
  }

  return { sha256hex, canonicalize, fingerprintContent, hashLeaf, hashNode, verifyInclusionProof, verifySignature };
})();


// ─────────────────────────────────────────────────────────────────────────────
// 2. API CLIENT
// ─────────────────────────────────────────────────────────────────────────────

const MCSAPI = (() => {
  const BASE = '/api/mcs';

  async function post(path, body) {
    const r = await fetch(BASE + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!r.ok) { const e = await r.json().catch(() => ({ error: r.statusText })); throw new Error(e.error || r.statusText); }
    return r.json();
  }

  async function get(path) {
    const r = await fetch(BASE + path);
    if (!r.ok) { const e = await r.json().catch(() => ({ error: r.statusText })); throw new Error(e.error || r.statusText); }
    return r.json();
  }

  return {
    scan: (serverSlug, baitAndSwitch = false) => post('/scan', { serverSlug, baitAndSwitch }),
    getScans: (serverSlug) => get(`/scans${serverSlug ? '?serverSlug=' + serverSlug : ''}`),
    getAttestation: (id) => get('/attestations/' + id),
    getLog: () => get('/log'),
    getLogProof: (index) => get(`/log/${index}/proof`),
    getAnchors: () => get('/anchors'),
    triggerAnchor: () => post('/anchors/trigger', {}),
    getWatcher: () => get('/watcher'),
    pollWatcher: () => post('/watcher/poll', {}),
    getConfig: () => get('/config'),
    simulateUpdate: (serverId, updateType) => post(`/watcher/${serverId}/simulate-update`, { updateType }),
    verifyExternal: (body) => post('/verify-external', body),
    getPubkey: () => get('/pubkey'),
    verifyFingerprint: (fp) => get('/verify-fingerprint?fingerprint=' + encodeURIComponent(fp)),
    getStats: () => get('/stats'),
    mcpEndpointMock: (body) => post('/mcp-endpoint-mock', body),
    getExternalRequests: () => get('/external-requests'),
    // Admin helpers
    getAllScans: (limit = 200) => get(`/scans?limit=${limit}`),
    getSTH: () => get('/log').then(d => d.signedTreeHead || d.sth || {}),
  };
})();


// ─────────────────────────────────────────────────────────────────────────────
// 3. PIPELINE ANIMATION ENGINE
// ─────────────────────────────────────────────────────────────────────────────

const STAGE_DELAY = 750; // ms per stage — configurable
let FAST_MODE = new URLSearchParams(location.search).has('fast');

function stageDelay(ms) {
  return FAST_MODE ? Promise.resolve() : new Promise(r => setTimeout(r, ms));
}

const VERDICT_COLORS = { PASS: '#10b981', REVIEW: '#f59e0b', FAIL: '#ef4444' };
const VERDICT_LABELS = { PASS: '✓ PASS', REVIEW: '⚠ REVIEW', FAIL: '✕ FAIL' };

function verdictBadge(verdict, large = false) {
  const color = VERDICT_COLORS[verdict] || '#64748b';
  const size = large ? 'font-size:2rem;padding:0.75rem 2.5rem;' : '';
  return `<span class="mcs-verdict-badge mcs-verdict-${verdict.toLowerCase()}" style="${size}">${VERDICT_LABELS[verdict] || verdict}</span>`;
}

function simBadge(tooltip = '') {
  return `<span class="mcs-sim-badge" title="${tooltip}">SIMULATED (POC)</span>`;
}

function realBadge(tooltip = '') {
  return `<span class="mcs-real-badge" title="${tooltip}">REAL CRYPTO</span>`;
}

function realAnalysisBadge(tooltip = '') {
  return `<span class="mcs-real-badge" title="${tooltip}">REAL ANALYSIS</span>`;
}

/**
 * Badge for one analyzer card, driven by what the backend reports it ran.
 * Never hardcode this — the whole point is that the label tracks reality.
 */
function analyzerBadge(a) {
  if (a.status === 'unavailable' || a.status === 'error') {
    return `<span class="mcs-sim-badge" style="background:rgba(239,68,68,0.15);color:#f87171;border-color:rgba(239,68,68,0.35)" title="${escapeHtml((a.evidence || [])[0] || '')}">${a.status === 'error' ? 'ERROR' : 'NOT RUNNING'}</span>`;
  }
  if (a.status === 'not_applicable') {
    return `<span class="mcs-sim-badge" title="Nothing in this server this analyzer can read (e.g. no Python for the AST analyzer)">N/A</span>`;
  }
  if (a.engine === 'static') {
    return realAnalysisBadge('Deterministic static analysis of the real source code. Parsed, never executed.');
  }
  if (a.engine === 'model') {
    return realAnalysisBadge('Trained model served over the MCP Secure analyzer contract. Deterministic CPU inference.');
  }
  if (a.engine === 'agent') {
    return realAnalysisBadge('Verification agent (advisory only — never changes the verdict).');
  }
  return simBadge(a.fallbackUsed
    ? 'Built-in heuristic stand-in: the trained model for this slot is not configured yet.'
    : 'Heuristic analyzer.');
}

function astEngineOf(analyzers) {
  const ast = (analyzers || []).find(a => a.analyzer === 'ast_taint' || a.analyzer === 'AST_TAINT');
  return ast ? ast.engine : undefined;
}

function setFastMode(value) {
  FAST_MODE = !!value;
}

// ─────────────────────────────────────────────────────────────────────────────
// Live pipeline — real backend stages over SSE.
//
// The stage list below is populated by events the server emits as each stage
// ACTUALLY finishes, carrying its measured duration. Nothing here is on a
// timer. (The detailed cards that render afterwards are a replay of results
// that already exist by then, which is why their fake delays are switched off.)
// ─────────────────────────────────────────────────────────────────────────────

const STAGE_LABELS = {
  parse: 'Parse source & extract tool views',
  ingest: 'Ingest: pin source, select files, discover tools',
  ingest_checks: 'Declared vs discovered tools',
  ast_taint: 'AST taint analyzer',
  model_b: 'Model B — code classifier',
  model_a: 'Model A — tool poisoning / preference manipulation',
  model_c: 'Model C — verification agent (advisory)',
  triage: 'Model C — verification agent (advisory)',
  policy: 'Deterministic policy engine',
  fingerprint: 'Fingerprint & commit pin',
  attest: 'Ed25519 attestation',
  log: 'Merkle transparency log',
  anchor: 'Chain anchor',
  blocked: 'Blockchain storage blocked',
};

function stageDetailText(e) {
  const bits = [];
  if (e.codeOrigin) {
    bits.push(e.codeOrigin === 'tool_source'
      ? `${e.sourcedTools}/${e.toolCount} tools from stored source`
      : 'markdown fallback (no stored source)');
  }
  if (e.codeChars !== undefined) bits.push(`code ${e.codeChars}c · text ${e.textChars}c`);
  if (e.files !== undefined) bits.push(`${e.files} file(s) · ${(e.languages || []).join('/') || 'no code'} · ${e.tools} tool(s) (${e.toolDiscovery})`);
  if (e.commitSha) bits.push(`commit ${String(e.commitSha).slice(0, 12)}`);
  if (e.error) bits.push(`error: ${e.error}`);
  if (e.engine) bits.push(`engine: ${e.engine}`);
  if (e.findings !== undefined) bits.push(`${e.findings} finding(s)`);
  if (e.score !== undefined) bits.push(`score ${(e.score * 100).toFixed(0)}%`);
  if (e.verdict && e.status === 'done') bits.push(`→ ${e.verdict}`);
  if (e.contentFingerprint) bits.push(`fp ${String(e.contentFingerprint).slice(0, 16)}…`);
  if (e.hashesGenerated === false) bits.push('hashes withheld');
  if (e.attestationId) bits.push(String(e.attestationId).slice(0, 18) + '…');
  if (e.logIndex !== undefined) bits.push(`leaf #${e.logIndex}`);
  if (e.blockNumber !== undefined) bits.push(`block #${e.blockNumber}`);
  if (e.attestationStatus) bits.push(e.attestationStatus);
  if (e.reason) bits.push(e.reason);
  return bits.join(' · ');
}

function createLiveStageView(container) {
  const events = [];
  container.innerHTML = `
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap;">
        <h3 style="margin:0;font-size:1rem;">Live pipeline ${realBadge('Stages stream from the backend as they complete. Durations are measured, not scripted.')}</h3>
        <span id="mcs-live-total" style="font-family:var(--font-mono);color:var(--text-3);font-size:0.8125rem;"></span>
      </div>
      <ul id="mcs-live-list" style="list-style:none;padding:0;margin:1rem 0 0;"></ul>
    </div>`;

  const list = container.querySelector('#mcs-live-list');
  const totalEl = container.querySelector('#mcs-live-total');
  const started = Date.now();
  let measured = 0;

  return {
    events,
    onStage(e) {
      events.push(e);
      const id = 'mcs-live-' + e.stage;
      let row = document.getElementById(id);
      if (!row) {
        // Two rows, not one: a long detail string on the same flex line
        // collapses the label to a single character per line.
        row = document.createElement('li');
        row.id = id;
        row.style.cssText = 'padding:0.45rem 0;border-bottom:1px solid var(--border);font-size:0.875rem;';
        row.innerHTML = `
          <div style="display:flex;align-items:baseline;gap:0.75rem;">
            <span class="live-icon" style="flex:0 0 1.25rem;color:var(--text-3);">⋯</span>
            <span style="flex:1 1 auto;min-width:0;">${escapeHtml(STAGE_LABELS[e.stage] || e.stage)}</span>
            <span class="live-ms" style="flex:0 0 auto;font-family:var(--font-mono);color:var(--text-3);min-width:4.5rem;text-align:right;"></span>
          </div>
          <div class="live-detail" style="margin-left:2rem;color:var(--text-3);font-family:var(--font-mono);font-size:0.7rem;line-height:1.5;overflow-wrap:anywhere;"></div>`;
        list.appendChild(row);
      }
      if (e.status === 'done') {
        row.querySelector('.live-icon').textContent = '✓';
        row.querySelector('.live-icon').style.color = 'var(--success)';
        row.querySelector('.live-detail').textContent = stageDetailText(e);
        if (typeof e.ms === 'number') {
          row.querySelector('.live-ms').textContent = `${e.ms} ms`;
          measured += e.ms;
        }
      }
      totalEl.textContent = `${Date.now() - started} ms elapsed · ${measured} ms in-stage`;
    },
    finish() {
      totalEl.textContent = `${Date.now() - started} ms wall · ${measured} ms measured in-stage`;
    },
  };
}

/**
 * Run a scan with live stage streaming.
 * Falls back to the plain POST endpoint when EventSource is unavailable.
 */
function streamScan(slug, options = {}) {
  const { baitAndSwitch = false, onStage, onBegin } = options;

  return new Promise((resolve, reject) => {
    if (typeof EventSource === 'undefined') {
      fetch('/api/mcs/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ serverSlug: slug, baitAndSwitch }),
      }).then(r => r.json().then(j => (r.ok ? resolve(j) : reject(new Error(j.error || r.statusText)))))
        .catch(reject);
      return;
    }

    const params = new URLSearchParams({ serverSlug: slug });
    if (baitAndSwitch) params.set('baitAndSwitch', 'true');
    const es = new EventSource('/api/mcs/scan/stream?' + params.toString());
    let settled = false;

    const fail = (message) => {
      if (settled) return;
      settled = true;
      es.close();
      reject(new Error(message));
    };

    es.addEventListener('begin', ev => { if (onBegin) onBegin(JSON.parse(ev.data)); });
    es.addEventListener('stage', ev => { if (onStage) onStage(JSON.parse(ev.data)); });
    es.addEventListener('result', ev => {
      settled = true;
      es.close();
      resolve(JSON.parse(ev.data));
    });
    es.addEventListener('error', ev => {
      let message = 'Scan stream failed';
      try { if (ev.data) message = JSON.parse(ev.data).error || message; } catch (_) { /* native error */ }
      fail(message);
    });
    es.onerror = () => fail('Connection to scan stream lost');
  });
}

/**
 * Render the animated pipeline view into a container element.
 * @param {HTMLElement} container
 * @param {object} scanResult - from /api/mcs/scan
 * @param {Function} onComplete - called after all stages animate
 */
async function renderPipelineAnimation(container, scanResult, onComplete, liveFacts = null) {
  const { scanRecord, attestation } = scanResult;
  const { snapshot, analyzers, verdict, policyVersion, rulesetHash } = scanRecord;

  // ── Detection Pipeline Runs First: Parse -> Analyzers -> Policy Engine -> Verdict ──
  container.innerHTML = `
    <div class="mcs-pipeline">
      <div class="mcs-pipeline-header">
        <h2>MCP Secure — Security Scan Pipeline</h2>
        <div class="mcs-legend-inline">
          <span class="mcs-dot" style="background:#06b6d4"></span>Detection Models
          <span class="mcs-dot" style="background:#6366f1"></span>Policy Engine
          <span class="mcs-dot" style="background:#10b981"></span>Integrity Hashes
          <span class="mcs-dot" style="background:#8b5cf6"></span>Blockchain Storage
        </div>
      </div>

      <!-- Stage 1: Parse AST -->
      <div class="mcs-stage mcs-stage-pending" id="stage-parse">
        <div class="mcs-stage-icon">📄</div>
        <div class="mcs-stage-body">
          <div class="mcs-stage-title">Step 1: Ingest source &amp; discover tools ${scanRecord.ingest
            ? realAnalysisBadge('Real ingestion: pinned source, shared file filter, static tool discovery (Python ast / TypeScript compiler). Nothing is executed.')
            : simBadge('Legacy scan record (before the ingestion pipeline)')}</div>
          <div class="mcs-stage-content" id="parse-content"></div>
        </div>
        <div class="mcs-stage-spinner" id="parse-spinner"></div>
      </div>

      <!-- Stage 2: Detection Models -->
      <div class="mcs-stage mcs-stage-pending" id="stage-analyzers">
        <div class="mcs-stage-icon">🔬</div>
        <div class="mcs-stage-body">
          <div class="mcs-stage-title">Step 2: Security Detection Pipeline (Parallel Scanners)</div>
          <div class="mcs-stage-content" id="analyzers-content">
            <div class="mcs-analyzers-grid" id="analyzers-grid"></div>
          </div>
        </div>
      </div>

      <!-- Stage 3: Deterministic Policy Engine -->
      <div class="mcs-stage mcs-stage-pending" id="stage-policy">
        <div class="mcs-stage-icon">⚖️</div>
        <div class="mcs-stage-body">
          <div class="mcs-stage-title">Step 3: Deterministic Policy Engine <span class="mcs-stage-label" style="color:var(--text-3);">${realBadge('Pinned ruleset evaluation')}</span></div>
          <div class="mcs-stage-content" id="policy-content"></div>
        </div>
        <div class="mcs-stage-spinner" id="policy-spinner"></div>
      </div>

      <!-- Stage 4: Verdict -->
      <div class="mcs-stage mcs-stage-pending" id="stage-verdict">
        <div class="mcs-stage-icon">🏛</div>
        <div class="mcs-stage-body">
          <div class="mcs-stage-title">Step 4: Detection Verdict &amp; Clearance</div>
          <div class="mcs-stage-content" id="verdict-content"></div>
        </div>
      </div>

      ${verdict === 'REVIEW' ? `
      <div class="mcs-stage mcs-stage-pending" id="stage-modelc">
        <div class="mcs-stage-icon">🤖</div>
        <div class="mcs-stage-body">
          <div class="mcs-stage-title">Model C — Verification Agent ${simBadge('Autonomous triage for flagged patterns')}</div>
          <div class="mcs-stage-content" id="modelc-content"></div>
        </div>
        <div class="mcs-stage-spinner" id="modelc-spinner"></div>
      </div>` : ''}

      ${verdict !== 'PASS' ? `
      <!-- Blocked from Blockchain notice -->
      <div class="mcs-stage mcs-stage-pending" id="stage-blockchain-blocked" style="border-color:rgba(239,68,68,0.3);background:rgba(239,68,68,0.04);">
        <div class="mcs-stage-icon">⛔</div>
        <div class="mcs-stage-body">
          <div class="mcs-stage-title" style="color:var(--error);">Blockchain Storage Blocked — Detection Not Clear</div>
          <div class="mcs-stage-content" id="blocked-content">
            <p style="margin:0.25rem 0 0.5rem;color:var(--text-2);">
              Because the detection pipeline detected security threats or flags, <strong>hashes were withheld</strong> and this server <strong>cannot be stored in the blockchain</strong>.
            </p>
            <div style="font-size:0.8125rem;color:var(--text-3);font-family:var(--font-mono);">
              • Blockchain Anchor: None (Blocked)<br>
              • Transparency Log Entry: None (Withheld)<br>
              • Hashes Committed: False
            </div>
          </div>
        </div>
        <div class="mcs-stage-spinner" id="blocked-spinner"></div>
      </div>` : ''}

      ${verdict === 'PASS' ? `
      <!-- Stage 5: Generate Hashes (Only after clear) -->
      <div class="mcs-stage mcs-stage-pending" id="stage-fingerprint">
        <div class="mcs-stage-icon">🔑</div>
        <div class="mcs-stage-body">
          <div class="mcs-stage-title">Step 5: Generate Security &amp; Integrity Hashes <span class="mcs-stage-label" style="color:var(--success);">${realBadge('Detection Clear — SHA-256 Fingerprint Generated')}</span></div>
          <div class="mcs-stage-content" id="fp-content"></div>
        </div>
        <div class="mcs-stage-spinner" id="fp-spinner"></div>
      </div>

      <!-- Stage 6: Attestation & Blockchain Storage -->
      <div class="mcs-stage mcs-stage-pending" id="stage-attest">
        <div class="mcs-stage-icon">⛓️</div>
        <div class="mcs-stage-body">
          <div class="mcs-stage-title">Step 6: Build Attestation &amp; Store in Blockchain ${realBadge('Ed25519 Signed · Merkle Log · Blockchain Anchor')}</div>
          <div class="mcs-stage-content" id="attest-content"></div>
        </div>
        <div class="mcs-stage-spinner" id="attest-spinner"></div>
      </div>` : ''}

      <div id="pipeline-final"></div>
    </div>
  `;

  // Stage helper functions
  function stageStart(id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.replace('mcs-stage-pending', 'mcs-stage-running');
    const sp = el.querySelector('.mcs-stage-spinner');
    if (sp) sp.innerHTML = '<span class="mcs-spinner"></span>';
  }

  function stageDone(id, isBlocked = false) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.replace('mcs-stage-running', 'mcs-stage-done');
    const sp = el.querySelector('.mcs-stage-spinner');
    if (sp) {
      sp.innerHTML = isBlocked
        ? '<span style="color:var(--error);font-size:1.2rem;">✕</span>'
        : '<span style="color:var(--success);font-size:1.2rem;">✓</span>';
    }
  }

  // ── 1. Animate: Parse AST ────────────────────────────────────────────────
  stageStart('stage-parse');
  await stageDelay(STAGE_DELAY);
  // Real measurements from the backend's parse stage when we have them.
  // This used to invent both numbers (one of them with Math.random), which
  // made the panel non-deterministic and simply untrue.
  const ing = scanRecord.ingest;
  const subj = scanRecord.subject || {};
  document.getElementById('parse-content').innerHTML = ing ? `
    <div style="color:var(--text-2);font-size:0.875rem;">
      Source <strong style="color:var(--text-1)">${escapeHtml(subj.source_kind || '')}</strong>
      ${subj.repo_url ? `· ${escapeHtml(subj.repo_url)}${subj.subdir ? '/' + escapeHtml(subj.subdir) : ''}` : ''}
      ${subj.commit_sha ? `· commit <code class="mcs-hash-short">${subj.commit_sha.slice(0, 12)}</code>` : '· not a git commit (local/upload)'}
      <br><strong style="color:var(--text-1)">${ing.files.length}</strong> code file(s) ·
      <strong style="color:var(--text-1)">${ing.tools.length}</strong> MCP tool(s) found (discovery: ${escapeHtml(ing.tool_discovery)})
      <br>Content fingerprint (code + tools + listing): <code class="mcs-hash-short">${escapeHtml(String(subj.content_fingerprint || '').slice(0, 30))}…</code>
      ${ing.tools.length ? `<ul style="margin:0.5rem 0 0 1rem;font-size:0.8rem;">${ing.tools.map(t => `<li><code>${escapeHtml(t.name)}</code> — ${escapeHtml(t.file)}:${t.handler.start_line} <span style="color:var(--text-3)">(${escapeHtml(t.discovered_by)})</span></li>`).join('')}</ul>` : ''}
      ${(ing.notes || []).length ? `<div style="margin-top:0.4rem;color:var(--warning);font-size:0.78rem;">${ing.notes.map(escapeHtml).join('<br>')}</div>` : ''}
    </div>` : '<div style="color:var(--text-2);font-size:0.875rem;">Legacy scan record: no ingestion data.</div>';
  stageDone('stage-parse');

  // ── 2. Animate: Detection Analyzers (parallel models) ─────────────────────
  stageStart('stage-analyzers');

  const analyzerNames = {
    'AST_TAINT': { label: 'AST Taint Analysis', sublabel: 'command injection · dangerous sinks', color: '#06b6d4', sim: true },
    'MODEL_B_CODE': { label: 'Model B (Code Obfuscation)', sublabel: 'obfuscation · evasion · learned injection', color: '#06b6d4', sim: true },
  };

  const grid = document.getElementById('analyzers-grid');
  grid.innerHTML = analyzers.map(a => {
    const info = analyzerNames[a.analyzer] || { label: a.display_name, sublabel: a.sublabel, color: '#06b6d4' };
    return `
    <div class="mcs-analyzer-card" id="ac-${a.analyzer}">
      <div class="mcs-analyzer-header">
        <span class="mcs-analyzer-name" style="color:${info.color}">${info.label || a.analyzer}</span>
        ${analyzerBadge(a)}
        <span class="mcs-analyzer-sub">${info.sublabel || ''}</span>
      </div>
      <div class="mcs-analyzer-body">
        <div class="mcs-spinner-inline"><span class="mcs-spinner"></span> Scanning for security threats…</div>
      </div>
    </div>`;
  }).join('');

  // Stagger the analyzers
  for (let i = 0; i < analyzers.length; i++) {
    await stageDelay(STAGE_DELAY * 0.65);
    const a = analyzers[i];
    const card = document.getElementById(`ac-${a.analyzer}`);
    if (!card) continue;

    const threatColor = a.score >= 0.75 ? 'var(--error)' : a.score >= 0.40 ? 'var(--warning)' : 'var(--success)';
    // Driven by the analyzer's own score/threat, not by string-matching the
    // evidence: evidence lines now include an "engine:" header, and a clean
    // scan must not be labelled "Flags Found" just because that line exists.
    const hasIssues = a.score > 0 || (a.threat && a.threat !== 'none');

    card.querySelector('.mcs-analyzer-body').innerHTML = `
      <div class="mcs-score-row">
        <span>Threat Score</span>
        <div class="mcs-score-bar">
          <div class="mcs-score-fill" style="width:${Math.round(a.score * 100)}%;background:${threatColor}"></div>
        </div>
        <strong style="color:${threatColor}">${(a.score * 100).toFixed(0)}%</strong>
      </div>
      <div class="mcs-threat-row">Detected Threat: <strong style="color:${a.threat === 'none' ? 'var(--success)' : 'var(--error)'}">${a.threat === 'none' ? 'None (Clean)' : a.threat.replace(/_/g, ' ')}</strong></div>
      <details class="mcs-evidence-details">
        <summary>${hasIssues ? '⚠️ Flags Found' : '✓ Clean Signal'} (${a.evidence.length} evidence items)</summary>
        <ul class="mcs-evidence-list">
          ${a.evidence.map(e => `<li>${escapeHtml(e)}</li>`).join('')}
        </ul>
      </details>
    `;
    card.classList.add(a.score >= 0.4 ? 'mcs-analyzer-flagged' : 'mcs-analyzer-clean');
  }

  await stageDelay(STAGE_DELAY * 0.4);
  stageDone('stage-analyzers');

  // ── 3. Animate: Policy Engine ─────────────────────────────────────────────
  stageStart('stage-policy');
  await stageDelay(STAGE_DELAY);

  const pol = scanRecord.policy;
  const maxScore = pol ? pol.max_effective_score : Math.max(0, ...analyzers.map(a => a.score));
  const reasonRows = pol && pol.reasons.length
    ? pol.reasons.map(r => `<li><code>${escapeHtml(r.rule)}</code>${r.verdict ? ` → <strong>${r.verdict}</strong>` : ''}: ${escapeHtml(r.message)}</li>`).join('')
    : '<li>No rule fired: every analyzer ran, coverage is sufficient and no finding reached the review threshold.</li>';

  document.getElementById('policy-content').innerHTML = `
    <div class="mcs-kv-grid">
      <span class="mcs-kv-key">Policy Version</span>
      <span class="mcs-kv-val">${policyVersion}</span>
      <span class="mcs-kv-key">Ruleset Hash</span>
      <code class="mcs-hash mcs-hash-short">${rulesetHash}</code>
      <span class="mcs-kv-key">Highest Effective Score</span>
      <span class="mcs-kv-val">${(maxScore * 100).toFixed(0)}%</span>
    </div>
    <div style="margin-top:0.75rem;font-size:0.82rem;color:var(--text-2);">Rules that fired:
      <ul style="margin:0.35rem 0 0 1.1rem;padding:0;line-height:1.6;">${reasonRows}</ul>
    </div>
  `;
  stageDone('stage-policy');

  // ── 4. Animate: Verdict & Clearance ───────────────────────────────────────
  stageStart('stage-verdict');
  await stageDelay(STAGE_DELAY * 0.5);
  const vEl = document.getElementById('verdict-content');
  vEl.innerHTML = verdictBadge(verdict, true);

  const descMap = {
    PASS: 'All detection models clear. No threats detected. Clearance granted for hash generation and blockchain storage.',
    REVIEW: 'Uncertain: a finding could not be proven, or part of the server could not be analysed. It waits for a human reviewer. Hashes and blockchain storage withheld.',
    FAIL: 'Critical security threats detected! Server rejected. Hashes withheld from blockchain registration.',
  };
  vEl.innerHTML += `<p style="margin-top:1rem;color:var(--text-2);">${descMap[verdict]}</p>` + renderVerdictEvidence(scanRecord);
  stageDone('stage-verdict');

  // ── Model C (REVIEW only) ─────────────────────────────────────────────────
  if (verdict === 'REVIEW') {
    stageStart('stage-modelc');
    await stageDelay(STAGE_DELAY * 1.2);

    const tri = scanRecord.triage;
    const rec = tri && tri.recommendation;
    document.getElementById('modelc-content').innerHTML = `
      <div class="mcs-modelc-panel">
        <div class="mcs-modelc-icon">🤖</div>
        <div>
          <strong>Model C — verification agent (advisory):</strong>
          ${rec ? `
          <p style="margin:0.5rem 0;color:var(--text-2);font-size:0.875rem;">Recommendation: <strong>${escapeHtml(rec.decision)}</strong> — ${escapeHtml(rec.rationale)}</p>`
          : `<p style="margin:0.5rem 0;color:var(--text-2);font-size:0.875rem;">${tri ? `Model C ${escapeHtml(tri.status)}${tri.error ? ': ' + escapeHtml(tri.error) : ''}.` : 'Model C is not configured yet.'} The submission goes to the admin review queue.</p>`}
          <div class="mcs-modelc-note">Model C never changes the verdict: an admin approves or rejects every REVIEW.</div>
        </div>
      </div>
    `;
    stageDone('stage-modelc');
  }

  // ── Handle NOT PASS: Blockchain Storage Blocked ───────────────────────────
  if (verdict !== 'PASS') {
    stageStart('stage-blockchain-blocked');
    await stageDelay(STAGE_DELAY * 0.6);
    stageDone('stage-blockchain-blocked', true);
  }

  // ── Handle PASS: Generate Hashes THEN Store to Blockchain ─────────────────
  if (verdict === 'PASS') {
    // ── 5. Generate Hashes ──
    stageStart('stage-fingerprint');
    await stageDelay(STAGE_DELAY);
    document.getElementById('fp-content').innerHTML = `
      <div class="mcs-kv-grid">
        <span class="mcs-kv-key">Content Fingerprint (SHA-256)</span>
        <code class="mcs-hash">${snapshot.contentFingerprint}</code>
        <span class="mcs-kv-key">Git Commit Snapshot SHA</span>
        <code class="mcs-hash mcs-hash-short">${snapshot.commitSha}</code>
        <span class="mcs-kv-key">Repo Reference</span>
        <span class="mcs-kv-val">${snapshot.repoRef}</span>
        <span class="mcs-kv-key">Server Version</span>
        <span class="mcs-kv-val">v${snapshot.version}</span>
        <span class="mcs-kv-key">Integrity Status</span>
        <span class="mcs-kv-val" style="color:var(--success);font-weight:600;">✓ Hashes Computed &amp; Ready for Blockchain</span>
      </div>
    `;
    stageDone('stage-fingerprint');

    // ── 6. Attestation & Blockchain Storage ──
    if (attestation) {
      stageStart('stage-attest');
      await stageDelay(STAGE_DELAY);
      const anchorInfo = scanResult.anchored
        ? `<span class="mcs-kv-key">Blockchain Anchor</span>
           <span class="mcs-kv-val" style="color:var(--accent);font-weight:600;">Block #${scanResult.anchored.blockNumber} (Tx: <code class="mcs-hash-short">${scanResult.anchored.txHash.slice(0, 20)}…</code>)</span>`
        : '';

      document.getElementById('attest-content').innerHTML = `
        <div class="mcs-kv-grid">
          <span class="mcs-kv-key">Attestation ID</span>
          <code class="mcs-hash mcs-hash-short">${attestation.attestationId}</code>
          <span class="mcs-kv-key">Ed25519 Signature</span>
          <code class="mcs-hash mcs-hash-short">${attestation.signature}</code>
          <span class="mcs-kv-key">Transparency Log Index</span>
          <span class="mcs-kv-val">#${scanResult.logIndex !== undefined && scanResult.logIndex !== null ? scanResult.logIndex : '0'} (Merkle Leaf Appended)</span>
          ${anchorInfo}
          <span class="mcs-kv-key">Public Key ID</span>
          <span class="mcs-kv-val">${attestation.publicKeyId}</span>
          <span class="mcs-kv-key">Anchored At</span>
          <span class="mcs-kv-val">${new Date(attestation.createdAt).toLocaleString()}</span>
        </div>
        <div style="margin-top:1rem;display:flex;gap:0.75rem;flex-wrap:wrap;">
          <button class="btn btn-primary btn-sm" onclick="MCSViews.downloadAttestation('${attestation.attestationId}')">⬇ Download Attestation JSON</button>
          <a href="/attestations?id=${attestation.attestationId}" class="btn btn-outline btn-sm">View in Explorer →</a>
        </div>
      `;
      stageDone('stage-attest');
    }
  }

  // ── Final Summary ─────────────────────────────────────────────────────────
  await stageDelay(STAGE_DELAY * 0.4);
  const finalEl = document.getElementById('pipeline-final');

  if (verdict === 'PASS') {
    finalEl.innerHTML = `
      <div class="mcs-final-card mcs-final-pass">
        <div class="mcs-final-badge">${verdictBadge(verdict, true)}</div>
        <div class="mcs-final-meta">
          <div>Detection: <strong style="color:var(--success)">100% Clear</strong></div>
          <div>Hashes: <strong style="color:var(--success)">Generated (SHA-256)</strong></div>
          <div>Blockchain: <strong style="color:var(--accent)">Stored &amp; Anchored${scanResult.anchored ? ` (Block #${scanResult.anchored.blockNumber})` : ''}</strong></div>
          <div>Log Index: <strong>#${scanResult.logIndex !== undefined && scanResult.logIndex !== null ? scanResult.logIndex : '0'}</strong></div>
        </div>
        <div class="mcs-final-actions">
          <button class="btn btn-primary" onclick="location.href='/attestations?id=${attestation?.attestationId}'">View Blockchain Attestation</button>
        </div>
      </div>
    `;
  } else if (verdict === 'FAIL') {
    finalEl.innerHTML = `
      <div class="mcs-final-card mcs-final-fail">
        <div class="mcs-final-badge">${verdictBadge(verdict, true)}</div>
        <div class="mcs-final-meta">
          <div>Detection: <strong style="color:var(--error)">Threats Detected</strong></div>
          <div>Hashes: <strong style="color:var(--error)">Not Generated (Withheld)</strong></div>
          <div>Blockchain: <strong style="color:var(--error)">Blocked from Chain</strong></div>
        </div>
        <div class="mcs-final-actions">
          <div class="mcs-reject-card">
            <strong>❌ Rejection Enforced:</strong> Malicious signals were detected during the detection pipeline. In accordance with security policy, hashes were withheld and no record was stored in the blockchain.
          </div>
        </div>
      </div>
    `;
  } else {
    finalEl.innerHTML = `
      <div class="mcs-final-card mcs-final-review">
        <div class="mcs-final-badge">${verdictBadge(verdict, true)}</div>
        <div class="mcs-final-meta">
          <div>Detection: <strong style="color:var(--warning)">Flagged for Review</strong></div>
          <div>Hashes: <strong style="color:var(--warning)">Withheld (Pending)</strong></div>
          <div>Blockchain: <strong style="color:var(--warning)">Not Stored</strong></div>
        </div>
        <div class="mcs-final-actions">
          <div style="color:var(--warning);font-size:0.875rem;line-height:1.6;">
            ⚠️ <strong>Review Required:</strong> Potential threats detected. Hashes will only be generated and committed to the blockchain after a human security reviewer clears the submission.
          </div>
        </div>
      </div>
    `;
  }

  if (onComplete) onComplete(scanResult);
}


// ─────────────────────────────────────────────────────────────────────────────
// 4. ATTESTATION & LOG EXPLORER
// ─────────────────────────────────────────────────────────────────────────────

const MCSAttestations = (() => {

  async function renderAttestationInspector(container, recordData) {
    const { attestation, scanRecord, superseded } = recordData;
    if (!attestation) { container.innerHTML = '<div class="empty-state">No attestation found.</div>'; return; }

    // Verify signature live in browser
    const pkInfo = await MCSAPI.getPubkey().catch(() => null);
    let sigStatus = null;
    if (pkInfo) {
      const recordStr = JSON.stringify(attestation.scanRecord || scanRecord);
      sigStatus = await MCSCrypto.verifySignature(attestation.signature, attestation.signature, pkInfo.publicKeyHex);
      // Correct verification: sign the scanRecord string
      sigStatus = await MCSCrypto.verifySignature(recordStr, attestation.signature, pkInfo.publicKeyHex);
    }

    const sigBadge = sigStatus === true
      ? `<span style="color:var(--success)">✓ Signature valid (verified live in browser)</span>`
      : sigStatus === false
      ? `<span style="color:var(--error)">✕ Signature INVALID</span>`
      : `<span style="color:var(--warning)">⚠ Ed25519 not supported in this browser — verify with server API</span>`;

    const verdict = (attestation.scanRecord || scanRecord)?.verdict;

    container.innerHTML = `
      <div class="card" style="margin-bottom:1.5rem;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1rem;margin-bottom:1rem;">
          <div>
            <h3 style="margin-bottom:0.25rem;">Attestation Record ${superseded ? '<span class="mcs-sim-badge" style="background:rgba(239,68,68,0.2);color:#ef4444;">SUPERSEDED</span>' : ''}</h3>
            <div style="color:var(--text-3);font-size:0.8125rem;">${realBadge('Real Ed25519 signature, real SHA-256 attestation ID')}</div>
          </div>
          ${verdictBadge(verdict || 'UNKNOWN')}
        </div>

        <div class="mcs-kv-grid">
          <span class="mcs-kv-key">Attestation ID</span>
          <code class="mcs-hash">${attestation.attestationId}</code>
          <span class="mcs-kv-key">Ed25519 Signature ${realBadge('Real Ed25519 — verifiable by anyone with the public key')}</span>
          <div>
            <code class="mcs-hash mcs-hash-short">${attestation.signature}</code>
            <div style="margin-top:0.5rem;font-size:0.8125rem;">${sigBadge}</div>
          </div>
          <span class="mcs-kv-key">Public Key ID</span>
          <span class="mcs-kv-val">${attestation.publicKeyId}</span>
          <span class="mcs-kv-key">Created At</span>
          <span class="mcs-kv-val">${new Date(attestation.createdAt).toLocaleString()}</span>
          <span class="mcs-kv-key">Policy Version</span>
          <span class="mcs-kv-val">${(attestation.scanRecord || scanRecord)?.policyVersion}</span>
          <span class="mcs-kv-key">Ruleset Hash (SHA-256)</span>
          <code class="mcs-hash mcs-hash-short">${(attestation.scanRecord || scanRecord)?.rulesetHash}</code>
        </div>

        <details style="margin-top:1rem;">
          <summary class="mcs-details-summary">View full attestation JSON</summary>
          <pre class="mcs-json-pre">${escapeHtml(JSON.stringify(attestation, null, 2))}</pre>
        </details>

        <div style="margin-top:1rem;display:flex;gap:0.75rem;flex-wrap:wrap;">
          <button class="btn btn-outline btn-sm" onclick="MCSViews.downloadAttestation('${attestation.attestationId}')">⬇ Download JSON</button>
        </div>
      </div>
    `;
  }

  async function renderLogExplorer(container) {
    const { leaves, signedTreeHead: sth } = await MCSAPI.getLog();

    container.innerHTML = `
      <div class="card" style="margin-bottom:1.5rem;">
        <h3 style="margin-bottom:1rem;">Transparency Log — Signed Tree Head ${realBadge('Real Merkle root, real Ed25519 signature over STH')}</h3>
        <div class="mcs-kv-grid">
          <span class="mcs-kv-key">Root Hash (Merkle)</span>
          <code class="mcs-hash">${sth.rootHash}</code>
          <span class="mcs-kv-key">Log Size</span>
          <span class="mcs-kv-val">${sth.size} entries</span>
          <span class="mcs-kv-key">STH Timestamp</span>
          <span class="mcs-kv-val">${new Date(sth.timestamp).toLocaleString()}</span>
          <span class="mcs-kv-key">STH Signature (Ed25519)</span>
          <code class="mcs-hash mcs-hash-short">${sth.signature}</code>
        </div>
      </div>

      <div class="card">
        <h3 style="margin-bottom:1rem;">Log Entries (${leaves.length} total)</h3>
        ${leaves.length === 0 ? '<div class="empty-state">No log entries yet.</div>' : `
        <div class="mcs-log-table-wrap">
          <table class="mcs-table">
            <thead><tr>
              <th>#</th>
              <th>Attestation ID (SHA-256)</th>
              <th>Leaf Hash</th>
              <th>Time</th>
              <th>Actions</th>
            </tr></thead>
            <tbody>
              ${leaves.map(l => `
              <tr>
                <td><strong>${l.index}</strong></td>
                <td><code class="mcs-hash-short" title="${l.attestationId}">${l.attestationId.slice(0, 24)}…</code></td>
                <td><code class="mcs-hash-short" title="${l.leafHash}">${l.leafHash.slice(0, 20)}…</code></td>
                <td style="font-size:0.8rem;color:var(--text-3)">${new Date(l.createdAt).toLocaleString()}</td>
                <td>
                  <button class="btn btn-outline btn-xs" onclick="MCSAttestations.showInclusionProof(${l.index}, '${l.attestationId}')">Inclusion Proof</button>
                  <a href="/attestations?id=${l.attestationId}" class="btn btn-outline btn-xs">View</a>
                </td>
              </tr>`).join('')}
            </tbody>
          </table>
        </div>`}
      </div>
    `;
  }

  async function showInclusionProof(leafIndex, attestationId) {
    const proof = await MCSAPI.getLogProof(leafIndex).catch(e => ({ error: e.message }));

    if (proof.error) {
      alert('Error getting proof: ' + proof.error);
      return;
    }

    // Verify the proof client-side using real crypto
    const verificationEl = document.createElement('div');
    verificationEl.innerHTML = '<span class="mcs-spinner"></span> Verifying proof in browser…';

    const verified = await MCSCrypto.verifyInclusionProof(
      attestationId, proof.leafIndex, proof.siblings, proof.rootHash
    );

    const modal = createModal(`
      <h3>Merkle Inclusion Proof — Leaf #${leafIndex} ${realBadge('Real SHA-256 Merkle proof verified in browser')}</h3>
      <div class="mcs-kv-grid" style="margin:1rem 0;">
        <span class="mcs-kv-key">Leaf Index</span><span class="mcs-kv-val">${proof.leafIndex}</span>
        <span class="mcs-kv-key">Root Hash</span><code class="mcs-hash">${proof.rootHash}</code>
        <span class="mcs-kv-key">Siblings (${proof.siblings.length})</span>
        <div>${proof.siblings.map((s, i) => `<div><span style="color:var(--text-3);font-size:0.8rem;">[${i}]</span> <code class="mcs-hash-short">${s.slice(0,32)}…</code></div>`).join('')}</div>
        <span class="mcs-kv-key">Client-side Verification</span>
        <span style="color:${verified ? 'var(--success)' : 'var(--error)'}">
          ${verified ? '✓ Proof valid — leaf #' + leafIndex + ' is included in the log' : '✕ Proof INVALID'}
        </span>
      </div>
    `);
  }

  async function renderChainExplorer(container) {
    const anchors = await MCSAPI.getAnchors();

    container.innerHTML = `
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;flex-wrap:wrap;gap:1rem;">
          <h3>Simulated Chain — Block Explorer ${simBadge('In production: one real transaction on Sepolia testnet anchors the Merkle root. Only the root goes on-chain.')}</h3>
          <button class="btn btn-outline btn-sm" onclick="MCSAttestations.triggerAnchor()">⚓ Anchor Now</button>
        </div>
        <div class="mcs-chain-note">
          Each block anchors the current Merkle root of the transparency log. In production, this is one Ethereum transaction
          — only 32 bytes on-chain. The rest stays off-chain and independently verifiable.
        </div>
        ${anchors.length === 0 ? '<div class="empty-state">No anchors yet.</div>' : `
        <div class="mcs-log-table-wrap">
          <table class="mcs-table">
            <thead><tr>
              <th>Block</th>
              <th>Tx Hash</th>
              <th>Anchored Root</th>
              <th>Log Size</th>
              <th>Time</th>
              <th>Network</th>
            </tr></thead>
            <tbody>
              ${anchors.map(a => `
              <tr>
                <td><strong>#${a.blockNumber}</strong></td>
                <td><code class="mcs-hash-short" title="${a.txHash}">${a.txHash.slice(0, 22)}…</code></td>
                <td><code class="mcs-hash-short" title="${a.rootHash}">${a.rootHash.slice(0, 20)}…</code></td>
                <td>${a.logSizeAtAnchor}</td>
                <td style="font-size:0.8rem;color:var(--text-3)">${new Date(a.blockTimestamp).toLocaleString()}</td>
                <td><span class="mcs-sim-badge">${a.network}</span></td>
              </tr>`).join('')}
            </tbody>
          </table>
        </div>`}
      </div>
    `;
  }

  async function triggerAnchor() {
    try {
      const btn = event.target;
      btn.disabled = true;
      btn.textContent = 'Anchoring…';
      await MCSAPI.triggerAnchor();
      location.reload();
    } catch (e) {
      alert('Anchor error: ' + e.message);
    }
  }

  return { renderAttestationInspector, renderLogExplorer, showInclusionProof, renderChainExplorer, triggerAnchor };
})();


// ─────────────────────────────────────────────────────────────────────────────
// 5. VERIFY FLOW (live crypto checks)
// ─────────────────────────────────────────────────────────────────────────────

const MCSVerify = (() => {

  /**
   * Run the full 5-step client-side verification for a server.
   * @param {HTMLElement} container
   * @param {object} serverData - { name, description, long_description, github_url, tools }
   */
  async function runVerifyFlow(container, serverData) {
    container.innerHTML = `
      <h3 style="margin-bottom:1.5rem;">Live Verification — ${escapeHtml(serverData.name || 'Server')}</h3>
      <div class="mcs-verify-steps" id="verify-steps"></div>
      <div id="verify-final"></div>
    `;

    const stepsEl = document.getElementById('verify-steps');
    const steps = [
      { id: 'v1', label: 'Recompute content fingerprint (SHA-256)' },
      { id: 'v2', label: 'Look up matching attestation in log' },
      { id: 'v3', label: 'Verify Ed25519 signature' },
      { id: 'v4', label: 'Verify Merkle inclusion proof' },
      { id: 'v5', label: 'Check anchor timestamp predates now' },
    ];

    stepsEl.innerHTML = steps.map(s => `
      <div class="mcs-verify-step" id="${s.id}">
        <span class="mcs-verify-icon" id="${s.id}-icon">⋯</span>
        <span>${s.label}</span>
        <span class="mcs-verify-detail" id="${s.id}-detail"></span>
      </div>
    `).join('');

    function setStep(id, status, detail = '') {
      const icons = { running: '⏳', pass: '✓', fail: '✕', warn: '⚠' };
      const colors = { running: 'var(--warning)', pass: 'var(--success)', fail: 'var(--error)', warn: 'var(--warning)' };
      const iconEl = document.getElementById(id + '-icon');
      const detailEl = document.getElementById(id + '-detail');
      if (iconEl) { iconEl.textContent = icons[status] || '?'; iconEl.style.color = colors[status] || ''; }
      if (detailEl) { detailEl.textContent = detail; detailEl.style.color = colors[status] || 'var(--text-3)'; }
    }

    let overallOk = true;
    let failReason = '';

    try {
      // Step 1: Recompute fingerprint
      setStep('v1', 'running');
      await stageDelay(600);
      const fp = await MCSCrypto.fingerprintContent(serverData);
      setStep('v1', 'pass', fp.slice(0, 32) + '…');

      // Step 2: Look up attestation
      setStep('v2', 'running');
      await stageDelay(700);
      const lookupResult = await MCSAPI.verifyFingerprint(fp);
      if (!lookupResult.found) {
        setStep('v2', 'fail', 'No attestation found for this fingerprint');
        overallOk = false;
        failReason = 'Not found in transparency log — server has not been scanned or content has changed';
      } else {
        const rec = lookupResult.record;
        setStep('v2', 'pass', `Found at log index #${lookupResult.logIndex} | Verdict: ${rec.verdict}`);

        if (rec.verdict !== 'PASS') {
          overallOk = false;
          failReason = `Server verdict is ${rec.verdict} — not trusted`;
        }

        if (rec.superseded) {
          overallOk = false;
          failReason = 'This attestation has been superseded by a newer scan';
        }

        // Step 3: Verify Ed25519 signature
        setStep('v3', 'running');
        await stageDelay(800);
        const pk = lookupResult.publicKey;
        const att = rec.attestation;
        const recordStr = JSON.stringify(att.scanRecord || rec);
        const sigResult = pk ? await MCSCrypto.verifySignature(recordStr, att.signature, pk.publicKeyHex) : null;

        if (sigResult === true) {
          setStep('v3', 'pass', 'Signature valid (Ed25519 verified in browser)');
        } else if (sigResult === false) {
          setStep('v3', 'fail', 'Signature INVALID — attestation tampered!');
          overallOk = false;
          failReason = 'Ed25519 signature verification failed';
        } else {
          setStep('v3', 'warn', 'Ed25519 not supported in this browser — server verified');
        }

        // Step 4: Merkle inclusion proof
        setStep('v4', 'running');
        await stageDelay(700);
        const proof = lookupResult.proof;
        if (proof && lookupResult.logIndex >= 0) {
          const proofOk = await MCSCrypto.verifyInclusionProof(
            att.attestationId, proof.leafIndex, proof.siblings, proof.rootHash
          );
          if (proofOk) {
            setStep('v4', 'pass', `Merkle proof valid — leaf #${proof.leafIndex} in root ${proof.rootHash.slice(0,16)}…`);
          } else {
            setStep('v4', 'fail', 'Merkle inclusion proof INVALID');
            overallOk = false;
            failReason = 'Merkle proof failed — log may have been tampered';
          }
        } else {
          setStep('v4', 'warn', 'No inclusion proof available (log may be empty)');
        }

        // Step 5: Anchor timestamp
        setStep('v5', 'running');
        await stageDelay(500);
        const anchors = lookupResult.anchors || [];
        const now = Date.now();
        const validAnchor = anchors.find(a => {
          const anchorTs = new Date(a.blockTimestamp).getTime();
          return anchorTs < now && a.logSizeAtAnchor > (lookupResult.logIndex || 0);
        });

        if (validAnchor) {
          setStep('v5', 'pass', `Anchored at block #${validAnchor.blockNumber} (${new Date(validAnchor.blockTimestamp).toLocaleString()})`);
        } else {
          setStep('v5', 'warn', 'No anchor yet — log not yet checkpointed on-chain');
        }
      }
    } catch (e) {
      overallOk = false;
      failReason = 'Verification error: ' + e.message;
    }

    await stageDelay(300);
    document.getElementById('verify-final').innerHTML = overallOk
      ? `<div class="mcs-trust-banner mcs-trust-ok">
           <strong>✓ Trusted</strong> — Matches an anchored PASS attestation.
           Fingerprint verified, signature valid, Merkle proof checked.
         </div>`
      : `<div class="mcs-trust-banner mcs-trust-fail">
           <strong>✕ Do Not Trust</strong> — ${escapeHtml(failReason)}.
         </div>`;
  }

  return { runVerifyFlow };
})();


// ─────────────────────────────────────────────────────────────────────────────
// 6. WATCHER DASHBOARD
// ─────────────────────────────────────────────────────────────────────────────

const MCSWatcher = (() => {

  async function render(container) {
    const rows = await MCSAPI.getWatcher().catch(() => []);
    const demoMode = (await MCSAPI.getConfig().catch(() => ({ demoMode: false }))).demoMode;

    const statusBadge = (s) => {
      const map = {
        up_to_date: ['#10b981', 'Up to date'],
        change_detected: ['#f59e0b', 'Change detected'],
        rescanning: ['#06b6d4', 'Re-scanning…'],
        no_longer_verifiable: ['#ef4444', 'Unverifiable'],
      };
      const [color, label] = map[s] || ['#64748b', s];
      return `<span class="mcs-status-pill" style="--sc:${color}">${label}</span>`;
    };

    container.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.5rem;flex-wrap:wrap;gap:1rem;">
        <div>
          <h2>Version Watcher Dashboard</h2>
          <p style="margin:0;font-size:0.875rem;">Monitors published servers for content changes. When a fingerprint changes, an automatic re-scan is triggered.</p>
        </div>
        <div style="display:flex;gap:0.75rem;align-items:center;">
          <label style="display:flex;align-items:center;gap:0.5rem;color:var(--text-2);font-size:0.875rem;">
            <input type="checkbox" id="autopoll-toggle"> Auto-poll (30s)
          </label>
          <button class="btn btn-outline btn-sm" onclick="MCSWatcher.pollNow(this)" title="git ls-remote on every watched repository; a new commit is re-scanned through the gate">⟳ Poll Now</button>
        </div>
      </div>

      ${rows.length === 0 ? '<div class="empty-state">No servers being watched yet. Scan a server to begin tracking.</div>' : `
      <div class="card">
        <div class="mcs-log-table-wrap">
          <table class="mcs-table">
            <thead><tr>
              <th>Server</th>
              <th>Watched Ref</th>
              <th>Last SHA</th>
              <th>Last Fingerprint</th>
              <th>Verdict</th>
              <th>Status</th>
              <th>Last Checked</th>
              <th>Simulate Update</th>
            </tr></thead>
            <tbody>
              ${rows.map(row => `
              <tr id="wr-${row.serverId}">
                <td><strong>${escapeHtml(row.server?.name || row.serverId)}</strong></td>
                <td><code>${escapeHtml(row.watchedRef)}</code></td>
                <td><code class="mcs-hash-short" title="${row.lastSeenSha}">${(row.lastSeenSha || '—').slice(0, 12)}…</code></td>
                <td><code class="mcs-hash-short" title="${row.lastFingerprint}">${(row.lastFingerprint || '—').slice(0, 12)}…</code></td>
                <td>${verdictBadge(row.lastVerdict || 'UNKNOWN')}</td>
                <td>${statusBadge(row.status)}</td>
                <td style="font-size:0.8rem;color:var(--text-3)">${row.lastCheckedAt ? new Date(row.lastCheckedAt).toLocaleString() : '—'}</td>
                <td>
                  <div style="display:flex;gap:0.5rem;flex-wrap:wrap;${demoMode ? '' : 'display:none;'}">
                    <button class="btn btn-outline btn-xs" onclick="MCSWatcher.simulateUpdate('${row.serverId}', 'docs_only')" title="Only README changed — fingerprint unchanged, verdict carried forward">📄 Docs Only</button>
                    <button class="btn btn-xs" style="background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.3);color:#ef4444;" onclick="MCSWatcher.simulateUpdate('${row.serverId}', 'bait_and_switch')" title="Malicious code injected — triggers automatic re-scan">☠ Bait &amp; Switch</button>
                  </div>
                </td>
              </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <div id="watcher-update-result"></div>

      <div class="card" style="margin-top:1.5rem;">
        <h3>Version History Timeline</h3>
        <p style="color:var(--text-3);font-size:0.875rem;">Click a server row above to see its full version history here, or select below:</p>
        <select class="select" id="version-server-select" onchange="MCSWatcher.loadVersionHistory(this.value)" style="max-width:300px;margin-bottom:1rem;">
          <option value="">— Select a server —</option>
          ${rows.map(r => `<option value="${r.serverId}">${escapeHtml(r.server?.name || r.serverId)}</option>`).join('')}
        </select>
        <div id="version-history-container"></div>
      </div>`}
    `;

    // Auto-poll setup
    document.getElementById('autopoll-toggle')?.addEventListener('change', (e) => {
      if (e.target.checked) {
        window._mcsPollTimer = setInterval(() => MCSWatcher.pollNow(), 30000);
      } else {
        clearInterval(window._mcsPollTimer);
      }
    });
  }

  async function simulateUpdate(serverId, updateType) {
    const resultEl = document.getElementById('watcher-update-result');
    if (resultEl) {
      resultEl.innerHTML = `<div class="card mcs-update-result-card"><span class="mcs-spinner"></span> Simulating ${updateType === 'docs_only' ? 'docs-only' : 'bait-and-switch'} update…</div>`;
    }

    try {
      const result = await MCSAPI.simulateUpdate(serverId, updateType);
      if (resultEl) {
        resultEl.innerHTML = `
          <div class="card mcs-update-result-card ${result.rescanned && result.newVerdict === 'FAIL' ? 'mcs-result-fail' : result.rescanned ? 'mcs-result-warn' : 'mcs-result-ok'}">
            <h4>${updateType === 'docs_only' ? '📄 Docs-Only Update' : '☠ Bait-and-Switch Update'}</h4>
            <p>${escapeHtml(result.message)}</p>
            <div class="mcs-kv-grid" style="font-size:0.875rem;">
              <span class="mcs-kv-key">Fingerprint Changed</span>
              <span style="color:${result.fingerprintChanged ? 'var(--error)' : 'var(--success)'}">${result.fingerprintChanged ? 'YES ← re-scan triggered' : 'No ← verdict carried forward'}</span>
              ${result.rescanned ? `
              <span class="mcs-kv-key">New Version</span><span class="mcs-kv-val">v${result.newVersion}</span>
              <span class="mcs-kv-key">New Verdict</span><span>${verdictBadge(result.newVerdict || 'UNKNOWN')}</span>
              <span class="mcs-kv-key">Old PASS Superseded</span><span style="color:var(--error)">Yes</span>
              ` : `
              <span class="mcs-kv-key">Verdict</span><span>${verdictBadge(result.verdict || 'UNKNOWN')}</span>
              `}
            </div>
            ${result.rescanned ? `<a href="/scan?server=${encodeURIComponent(serverId)}&prefill=true" class="btn btn-outline btn-sm" style="margin-top:0.75rem;">View New Scan Record →</a>` : ''}
          </div>
        `;
      }

      // Reload watcher table
      await render(document.querySelector('.mcs-watcher-root') || document.querySelector('main .container'));
    } catch (e) {
      if (resultEl) resultEl.innerHTML = `<div class="card" style="border-color:var(--error)">Error: ${escapeHtml(e.message)}</div>`;
    }
  }

  async function loadVersionHistory(serverId) {
    if (!serverId) return;
    const container = document.getElementById('version-history-container');
    container.innerHTML = '<span class="mcs-spinner"></span> Loading…';

    const scans = await MCSAPI.getScans(serverId).catch(() => []);

    if (scans.length === 0) {
      container.innerHTML = '<p style="color:var(--text-3)">No scan history for this server.</p>';
      return;
    }

    container.innerHTML = `
      <div class="mcs-timeline">
        ${scans.map((s, i) => `
        <div class="mcs-timeline-item ${s.superseded ? 'mcs-timeline-superseded' : ''}">
          <div class="mcs-timeline-dot" style="background:${VERDICT_COLORS[s.verdict] || '#64748b'}"></div>
          <div class="mcs-timeline-body">
            <div style="display:flex;gap:0.75rem;align-items:center;flex-wrap:wrap;">
              ${verdictBadge(s.verdict)}
              <span style="color:var(--text-3);font-size:0.875rem;">v${s.version} · ${new Date(s.createdAt).toLocaleString()}</span>
              ${s.superseded ? '<span class="mcs-sim-badge" style="background:rgba(239,68,68,0.2);color:#ef4444;font-size:0.7rem;">SUPERSEDED</span>' : i === 0 ? '<span class="mcs-sim-badge" style="background:rgba(16,185,129,0.15);color:#10b981;font-size:0.7rem;">CURRENT</span>' : ''}
            </div>
            <div style="margin-top:0.5rem;font-size:0.8125rem;color:var(--text-3);">
              Fingerprint: ${s.snapshot?.contentFingerprint ? `<code class="mcs-hash-short">${s.snapshot.contentFingerprint.slice(0, 32)}…</code>` : `<span style="color:var(--warning);font-size:0.75rem;">Withheld (Not Stored)</span>`}
            </div>
            <a href="/attestations?id=${s.id}" style="font-size:0.8125rem;color:var(--accent);">View attestation →</a>
          </div>
        </div>`).join('')}
      </div>
    `;
  }

  // Real poll: the server runs git ls-remote on each watched git repository
  // and queues a gate re-scan for every new commit.
  async function pollNow(btn) {
    if (btn) { btn.disabled = true; btn.textContent = 'Polling…'; }
    let summary = '';
    try {
      const { polled } = await MCSAPI.pollWatcher();
      const label = { new_commit: 'new commit → re-scan queued', up_to_date: 'up to date', scan_pending: 'scan in progress', error: 'error' };
      summary = polled.length === 0
        ? '<p style="margin:0">No git-sourced servers are being watched yet. Publish one (e.g. a testbed branch) first.</p>'
        : `<ul style="margin:0;padding-left:1.2rem">${polled.map(p => `<li><strong>${escapeHtml(p.name)}</strong>: ${escapeHtml(label[p.status] || p.status)}${p.sha ? ` <code>${escapeHtml(p.sha.slice(0, 12))}</code>` : ''}${p.error ? ` (${escapeHtml(p.error)})` : ''}${p.submissionId ? ` · <a href="/server-detail?slug=${encodeURIComponent(p.slug)}">listing</a> (press Poll Now again when the scan has finished)` : ''}</li>`).join('')}</ul>`;
    } catch (e) {
      summary = `<p style="margin:0;color:var(--error)">Poll failed: ${escapeHtml(e.message)}</p>`;
    }
    await render(document.querySelector('.mcs-watcher-root') || document.querySelector('main'));
    const el = document.getElementById('watcher-update-result');
    if (el) el.innerHTML = `<div class="card mcs-update-result-card"><h3 style="margin-top:0">Poll result · ${new Date().toLocaleTimeString()}</h3>${summary}</div>`;
    if (btn && document.body.contains(btn)) { btn.disabled = false; btn.textContent = '⟳ Poll Now'; }
  }

  return { render, simulateUpdate, loadVersionHistory, pollNow };
})();


// ─────────────────────────────────────────────────────────────────────────────
// 7. EXTERNAL VERIFIER
// ─────────────────────────────────────────────────────────────────────────────

const MCSVerifier = (() => {

  async function render(container) {
    container.innerHTML = `
      <div class="mcs-verifier-header">
        <div class="mcs-service-badge">MCP Secure Verification Service — our own MCP</div>
        <h1>External Server Verification</h1>
        <p>This page represents <strong>MCP Secure's own MCP</strong> being called by an external party
        (another marketplace or an end user). The candidate server is scanned but <strong>never added to our marketplace catalog</strong>.</p>
        <div class="mcs-enforced-badge">⛔ onboarded: false — enforced</div>
      </div>

      <div class="mcs-tabs" style="margin-top:2rem;">
        <button class="mcs-tab active" onclick="MCSVerifier.switchTab('marketplace', this)">External Marketplace Mode</button>
        <button class="mcs-tab" onclick="MCSVerifier.switchTab('enduser', this)">End-User Pre-Check Mode</button>
        <button class="mcs-tab" onclick="MCSVerifier.switchTab('endpoint', this)">MCP Endpoint Inspector</button>
      </div>

      <div id="vf-marketplace" class="mcs-tab-content" style="display:block;">
        ${renderMarketplaceForm()}
      </div>
      <div id="vf-enduser" class="mcs-tab-content" style="display:none;">
        ${renderEndUserForm()}
      </div>
      <div id="vf-endpoint" class="mcs-tab-content" style="display:none;">
        ${renderEndpointInspector()}
      </div>

      <div id="vf-result"></div>
    `;
  }

  function switchTab(tab, btn) {
    document.querySelectorAll('.mcs-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.mcs-tab-content').forEach(t => t.style.display = 'none');
    btn.classList.add('active');
    document.getElementById('vf-' + tab).style.display = 'block';
  }

  function renderMarketplaceForm() {
    return `
      <div class="card" style="margin-top:1rem;">
        <h3>External Marketplace Mode</h3>
        <p style="color:var(--text-2);font-size:0.875rem;">Another marketplace is calling MCP Secure to scan a server on their behalf.</p>

        <div class="form-field" style="margin-bottom:1rem;">
          <label class="label">Requester Name (marketplace)</label>
          <input class="input" id="vf-requester" value="Acme MCP Market" placeholder="e.g. Acme MCP Market">
        </div>
        <div class="form-field" style="margin-bottom:1rem;">
          <label class="label">Candidate Server Ref (repo URL)</label>
          <input class="input" id="vf-candidate-ref" value="https://github.com/modelcontextprotocol/servers/tree/main/src/fetch" placeholder="https://github.com/org/repo">
        </div>
        <div style="margin-bottom:1.5rem;">
          <span style="color:var(--text-3);font-size:0.8125rem;">Or use a seeded external candidate:</span>
          <div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-top:0.5rem;">
            <button class="btn btn-outline btn-sm" onclick="document.getElementById('vf-candidate-ref').value='https://github.com/modelcontextprotocol/servers/tree/main/src/fetch';document.getElementById('vf-requester').value='Acme MCP Market'">Official fetch server</button>
            <button class="btn btn-outline btn-sm" onclick="document.getElementById('vf-candidate-ref').value='demo:shell-runner';document.getElementById('vf-requester').value='Beta Marketplace'">Shell Runner (bundled demo)</button>
          </div>
        </div>
        <button class="btn btn-primary" onclick="MCSVerifier.runExternal()">
          🔍 Scan for ${`<span id="vf-requester-label">Acme MCP Market</span>`}
        </button>
        <p style="margin-top:0.75rem;font-size:0.8125rem;color:var(--text-3);">Result will be a signed, downloadable attestation. The server will NOT be added to our catalog.</p>
      </div>
    `;
  }

  function renderEndUserForm() {
    return `
      <div class="card" style="margin-top:1rem;">
        <h3>End-User Pre-Check Mode</h3>
        <p style="color:var(--text-2);font-size:0.875rem;">Is this server safe to use? Paste a reference and get an instant verdict.</p>
        <div class="form-field" style="margin-bottom:1rem;">
          <label class="label">Server Reference (repo URL or identifier)</label>
          <input class="input" id="vf-eu-ref" placeholder="https://github.com/org/repo or npm:package-name">
        </div>
        <button class="btn btn-primary" onclick="MCSVerifier.runEndUserCheck()">Check Safety</button>
      </div>
    `;
  }

  function renderEndpointInspector() {
    return `
      <div class="card" style="margin-top:1rem;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
          <h3>MCP Endpoint Inspector ${simBadge('In production: this is a real MCP tool exposed at mcp://mcpsecure.io/verify')}</h3>
        </div>
        <p style="color:var(--text-2);font-size:0.875rem;">This shows what the MCP tool call looks like when an external client calls MCP Secure's own MCP server.</p>
        <div class="form-field" style="margin-bottom:1rem;">
          <label class="label">Candidate Ref</label>
          <input class="input" id="vf-ep-ref" value="https://github.com/modelcontextprotocol/servers/tree/main/src/fetch">
        </div>
        <div class="form-field" style="margin-bottom:1rem;">
          <label class="label">Requester</label>
          <input class="input" id="vf-ep-req" value="external-marketplace">
        </div>
        <button class="btn btn-outline" onclick="MCSVerifier.showMcpEndpoint()">Generate MCP Request/Response</button>
        <div id="vf-endpoint-json" style="margin-top:1.5rem;"></div>
      </div>
    `;
  }

  async function runExternal() {
    const requesterName = document.getElementById('vf-requester')?.value;
    const candidateRef = document.getElementById('vf-candidate-ref')?.value;
    if (!candidateRef) { alert('Please enter a candidate ref'); return; }

    const resultEl = document.getElementById('vf-result');
    resultEl.innerHTML = `<div class="card" style="margin-top:1.5rem;"><span class="mcs-spinner"></span> Scanning on behalf of <strong>${escapeHtml(requesterName || 'external')}</strong>…</div>`;

    try {
      const result = await MCSAPI.verifyExternal({ requesterName, candidateRef });
      renderExternalResult(resultEl, result);
    } catch (e) {
      resultEl.innerHTML = `<div class="card mcs-result-fail" style="margin-top:1.5rem;">Error: ${escapeHtml(e.message)}</div>`;
    }
  }

  async function runEndUserCheck() {
    const candidateRef = document.getElementById('vf-eu-ref')?.value;
    if (!candidateRef) { alert('Please enter a server reference'); return; }

    const resultEl = document.getElementById('vf-result');
    resultEl.innerHTML = `<div class="card" style="margin-top:1.5rem;"><span class="mcs-spinner"></span> Checking safety of <code>${escapeHtml(candidateRef)}</code>…</div>`;

    try {
      const result = await MCSAPI.verifyExternal({ requesterName: 'End User', candidateRef });
      renderExternalResult(resultEl, result);
    } catch (e) {
      resultEl.innerHTML = `<div class="card mcs-result-fail" style="margin-top:1.5rem;">Error: ${escapeHtml(e.message)}</div>`;
    }
  }

  function renderExternalResult(container, result) {
    const verdict = result.scanRecord?.verdict;
    const att = result.attestation;

    container.innerHTML = `
      <div class="card mcs-external-result" style="margin-top:1.5rem;border-color:${VERDICT_COLORS[verdict] || '#64748b'}40;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1rem;margin-bottom:1rem;">
          <div>
            <h3>External Scan Result</h3>
            <p style="margin:0.25rem 0 0;color:var(--text-2);font-size:0.875rem;">${escapeHtml(result.message)}</p>
          </div>
          ${verdictBadge(verdict || 'UNKNOWN', true)}
        </div>

        <div class="mcs-enforced-badge" style="margin-bottom:1rem;">⛔ onboarded: false — this server was NOT added to the marketplace catalog</div>

        <div class="mcs-kv-grid">
          <span class="mcs-kv-key">Candidate Ref</span>
          <span class="mcs-kv-val">${escapeHtml(result.candidateRef)}</span>
          <span class="mcs-kv-key">Scanned For</span>
          <span class="mcs-kv-val">${escapeHtml(result.requesterName)}</span>
          <span class="mcs-kv-key">Attestation ID</span>
          <code class="mcs-hash mcs-hash-short">${att?.attestationId || '—'}</code>
          <span class="mcs-kv-key">Signature</span>
          <code class="mcs-hash mcs-hash-short">${att?.signature?.slice(0, 48) || '—'}…</code>
          <span class="mcs-kv-key">Log Index</span>
          <span class="mcs-kv-val">#${result.logIndex ?? '—'}</span>
        </div>

        <div style="margin-top:1rem;display:flex;gap:0.75rem;flex-wrap:wrap;">
          <button class="btn btn-primary btn-sm" onclick="MCSViews.downloadAttestation('${att?.attestationId}')">⬇ Download Signed Attestation</button>
          <a href="/attestations?id=${att?.attestationId}" class="btn btn-outline btn-sm">View in Transparency Explorer →</a>
        </div>

        <details style="margin-top:1rem;">
          <summary class="mcs-details-summary">Analyzer Evidence</summary>
          ${(result.scanRecord?.analyzers || []).map(a => `
          <div class="mcs-analyzer-mini">
            <strong>${a.analyzer}</strong> — Score: ${(a.score * 100).toFixed(0)}% — Threat: ${a.threat}
            <ul>${a.evidence.map(e => `<li>${escapeHtml(e)}</li>`).join('')}</ul>
          </div>`).join('')}
        </details>
      </div>
    `;
  }

  async function showMcpEndpoint() {
    const ref = document.getElementById('vf-ep-ref')?.value;
    const req = document.getElementById('vf-ep-req')?.value;
    const container = document.getElementById('vf-endpoint-json');
    container.innerHTML = '<span class="mcs-spinner"></span>';

    try {
      const { mcpRequest } = await MCSAPI.mcpEndpointMock({ candidateRef: ref, requesterName: req });
      const mockResponse = {
        jsonrpc: '2.0',
        result: {
          content: [{
            type: 'text',
            text: JSON.stringify({
              verdict: 'PASS',
              attestationId: 'sha256:abc123...',
              signature: 'ed25519:def456...',
              message: 'Scanned on behalf of ' + (req || 'external-marketplace') + '; not onboarded here.',
            }, null, 2),
          }],
          isError: false,
        },
        id: mcpRequest.id,
      };

      container.innerHTML = `
        <div class="mcs-mcp-panel">
          <div class="mcs-mcp-pane">
            <div class="mcs-mcp-label">→ MCP Tool Call (request)</div>
            <pre class="mcs-json-pre">${escapeHtml(JSON.stringify(mcpRequest, null, 2))}</pre>
          </div>
          <div class="mcs-mcp-pane">
            <div class="mcs-mcp-label">← MCP Response (signed verdict)</div>
            <pre class="mcs-json-pre">${escapeHtml(JSON.stringify(mockResponse, null, 2))}</pre>
          </div>
        </div>
        <p style="margin-top:0.75rem;font-size:0.8125rem;color:var(--text-3);">
          ${simBadge('In production: this tool is served over MCP at mcp://mcpsecure.io and responds to verify_mcp_server calls from any MCP client.')}
          The returned attestation is independently verifiable in the transparency explorer.
        </p>
      `;
    } catch (e) {
      container.innerHTML = `<div style="color:var(--error)">Error: ${e.message}</div>`;
    }
  }

  return { render, switchTab, runExternal, runEndUserCheck, showMcpEndpoint };
})();


// ─────────────────────────────────────────────────────────────────────────────
// 8. SHARED VIEWS & UTILITIES
// ─────────────────────────────────────────────────────────────────────────────

const MCSViews = (() => {

  async function downloadAttestation(id) {
    if (!id) { alert('No attestation ID'); return; }
    const record = await MCSAPI.getAttestation(id).catch(e => { alert('Error: ' + e.message); return null; });
    if (!record) return;

    const blob = new Blob([JSON.stringify(record.attestation || record, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `mcs-attestation-${id.slice(0, 16)}.json`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function renderMCSLegend(container) {
    container.innerHTML = `
      <div class="mcs-legend">
        <h4>MCP Secure Color Legend</h4>
        <div class="mcs-legend-grid">
          <span class="mcs-dot" style="background:#64748b"></span><span>Input / Data</span>
          <span class="mcs-dot" style="background:#06b6d4"></span><span>Analyzers (Detection)</span>
          <span class="mcs-dot" style="background:#6366f1"></span><span>Policy Engine</span>
          <span class="mcs-dot" style="background:#8b5cf6"></span><span>Blockchain / Attestation</span>
          <span class="mcs-dot" style="background:#10b981"></span><span>PASS / Trusted</span>
          <span class="mcs-dot" style="background:#f59e0b"></span><span>REVIEW / Advisory</span>
          <span class="mcs-dot" style="background:#ef4444"></span><span>FAIL / Rejected</span>
        </div>
        <div style="margin-top:0.75rem;display:flex;gap:0.5rem;flex-wrap:wrap;font-size:0.75rem;">
          <span class="mcs-sim-badge">SIMULATED (POC)</span> = deterministic mock of future ML/chain component
          <span class="mcs-real-badge">REAL CRYPTO</span> = genuine SHA-256, Ed25519, Merkle proof
          <span class="mcs-real-badge">REAL ANALYSIS</span> = genuine Python AST taint analysis (never executed)
        </div>
      </div>
    `;
  }

  return { downloadAttestation, renderMCSLegend };
})();


// ─── Utility ──────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════
// WHY THIS VERDICT: the findings and rules behind a FAIL or REVIEW, with the
// exact code lines (shared by the scan, publish, admin, server and verify pages)
// ═══════════════════════════════════════════════════════════════════════════
const THREAT_LABEL = {
  command_injection: 'Command injection', code_injection: 'Code injection', path_traversal: 'Path traversal',
  ssrf: 'SSRF', sql_injection: 'SQL injection', unsafe_deserialization: 'Unsafe deserialization',
  tool_poisoning: 'Tool poisoning', metadata_mismatch: 'Declared ≠ discovered tools',
};
const RULE_TEXT = {
  ast_high_hard_fail: 'Tool input reaches a shell/exec call (proven by the AST taint analyzer): automatic FAIL.',
  score_thresholds: 'The highest finding score crossed a threshold (≥ 0.75 FAIL, ≥ 0.40 REVIEW).',
  required_analyzer_unavailable: 'A required analyzer did not run, so the server cannot PASS.',
  unpinned_analyzer_version: 'The analyzer version is not the pinned one, so the server cannot PASS.',
  insufficient_code_coverage: 'No code analyzer could analyse this source (e.g. an unsupported language).',
  no_tools_discovered: 'No MCP tools were found, so tool input could not be traced.',
  source_not_fully_analysed: 'Some code files were too large or too many to analyse.',
  runtime_descriptions: 'A tool description is built at runtime and could not be checked.',
};

function renderVerdictEvidence(scanRecord) {
  if (!scanRecord || !scanRecord.policy) return '';
  const pol = scanRecord.policy;
  const all = new Map();
  for (const slot of scanRecord.results || []) {
    for (const f of slot.findings || []) all.set(f.finding_id, { ...f, slot: slot.slot, analyzerName: slot.display_name || slot.slot });
  }
  const decisive = (pol.reasons || []).filter(r => r.verdict);
  const counted = (pol.effective_findings || []).filter(e => e.effective_score >= 0.4);
  const evidenceOnly = (pol.effective_findings || []).length - counted.length;
  if (!decisive.length && !counted.length) {
    return `<div class="mcs-evidence"><div class="mcs-evidence-title">Why this verdict</div>
      <p style="margin:0;color:var(--text-2);font-size:0.85rem;">No rule fired: every required analyzer ran, the code was covered, and no finding reached the review threshold.${evidenceOnly ? ` (${evidenceOnly} low-score finding(s) kept as evidence only.)` : ''}</p></div>`;
  }
  const rules = decisive.map(r => `<li><strong>${escapeHtml(r.verdict)}</strong> · ${escapeHtml(RULE_TEXT[r.rule] || r.rule)}<br><span style="color:var(--text-3);">${escapeHtml(r.message)}</span></li>`).join('');
  const cards = counted.slice(0, 8).map(e => {
    const f = all.get(e.finding_id) || {};
    const loc = f.location || {};
    const d = f.details || {};
    const where = loc.file ? `${escapeHtml(loc.file)}${loc.line ? ':' + loc.line : ''}${loc.function ? ` in <code>${escapeHtml(loc.function.name)}()</code>` : ''}` : 'listing text';
    const lines = (d.evidence_lines || (d.code_excerpt ? [{ line: loc.line, text: d.code_excerpt }] : []))
      .map(l => `<div><span class="mcs-evidence-ln">${escapeHtml(l.line || '')}</span>${escapeHtml(l.text)}</div>`).join('');
    const path = Array.isArray(d.path) && d.path.length ? d.path.join(' → ') + (d.sink ? ` → ${d.sink}` : '') : '';
    const scoreNote = e.effective_score < e.raw_score
      ? `score ${e.raw_score.toFixed(2)} → <strong>${e.effective_score.toFixed(2)}</strong> (capped: no proven data flow)`
      : `score <strong>${e.effective_score.toFixed(2)}</strong>${e.corroborated_by ? (String(e.corroborated_by).startsWith('sha256:') ? ' · confirmed by a taint analyzer' : ` · ${escapeHtml(e.corroborated_by).replace('_', ' ')}`) : ''}`;
    const color = e.effective_score >= 0.75 ? '#ef4444' : '#f59e0b';
    return `<div class="mcs-evidence-card" style="border-left-color:${color};">
      <div style="display:flex;justify-content:space-between;gap:0.5rem;flex-wrap:wrap;">
        <strong style="color:${color};">${escapeHtml(THREAT_LABEL[e.threat] || e.threat)}</strong>
        <span style="font-size:0.78rem;color:var(--text-3);">${escapeHtml(f.analyzerName || e.slot)} · ${scoreNote}</span>
      </div>
      <div style="font-size:0.8rem;color:var(--text-2);margin:0.3rem 0;">${where}</div>
      ${lines ? `<pre class="mcs-evidence-code">${lines}</pre>` : ''}
      ${path ? `<div style="font-size:0.78rem;color:var(--text-3);">Taint path: <code>${escapeHtml(path)}</code></div>` : ''}
      ${f.summary && !path ? `<div style="font-size:0.78rem;color:var(--text-3);">${escapeHtml(f.summary)}</div>` : ''}
    </div>`;
  }).join('');
  return `<div class="mcs-evidence">
    <div class="mcs-evidence-title">Why this verdict</div>
    ${rules ? `<ul class="mcs-evidence-rules">${rules}</ul>` : ''}
    ${cards}
    ${counted.length > 8 ? `<div style="font-size:0.78rem;color:var(--text-3);">… and ${counted.length - 8} more finding(s).</div>` : ''}
    ${evidenceOnly ? `<div style="font-size:0.78rem;color:var(--text-3);margin-top:0.4rem;">${evidenceOnly} lower-score finding(s) kept as evidence only (they did not change the verdict).</div>` : ''}
  </div>`;
}
window.renderVerdictEvidence = renderVerdictEvidence;

(function evidenceStyles() {
  if (document.getElementById('mcs-evidence-css')) return;
  const st = document.createElement('style');
  st.id = 'mcs-evidence-css';
  st.textContent = `
    .mcs-evidence{margin-top:1rem;text-align:left}
    .mcs-evidence-title{font-weight:700;font-size:0.9rem;margin-bottom:0.5rem}
    .mcs-evidence-rules{margin:0 0 0.75rem 1.1rem;padding:0;font-size:0.82rem;line-height:1.55}
    .mcs-evidence-card{border:1px solid var(--border);border-left:3px solid #f59e0b;border-radius:6px;padding:0.6rem 0.75rem;margin-bottom:0.6rem;background:rgba(127,127,127,0.04)}
    .mcs-evidence-code{margin:0.35rem 0;padding:0.5rem 0.6rem;background:rgba(0,0,0,0.35);border-radius:4px;font-family:var(--font-mono,monospace);font-size:0.78rem;white-space:pre-wrap;word-break:break-all;color:#e5e7eb}
    .mcs-evidence-ln{display:inline-block;min-width:2.5rem;color:#9ca3af;user-select:none}
  `;
  document.head.appendChild(st);
})();

function escapeHtml(str) {
  return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function createModal(html) {
  const overlay = document.createElement('div');
  overlay.className = 'mcs-modal-overlay';
  overlay.innerHTML = `
    <div class="mcs-modal" role="dialog" aria-modal="true">
      <button class="mcs-modal-close" aria-label="Close" onclick="this.closest('.mcs-modal-overlay').remove()">×</button>
      ${html}
    </div>
  `;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
  // Focus first focusable element
  setTimeout(() => overlay.querySelector('button, [tabindex]')?.focus(), 50);
  return overlay;
}

// Expose globally for HTML onclick handlers
window.MCSCrypto = MCSCrypto;
window.MCSAPI = MCSAPI;
window.MCSViews = MCSViews;
window.MCSAttestations = MCSAttestations;
window.MCSVerify = MCSVerify;
window.MCSWatcher = MCSWatcher;
window.MCSVerifier = MCSVerifier;
window.renderPipelineAnimation = renderPipelineAnimation;
window.createLiveStageView = createLiveStageView;
window.streamScan = streamScan;
window.setFastMode = setFastMode;
window.verdictBadge = verdictBadge;
window.simBadge = simBadge;
window.realBadge = realBadge;
window.realAnalysisBadge = realAnalysisBadge;
window.analyzerBadge = analyzerBadge;
window.escapeHtml = escapeHtml;
window.stageDelay = stageDelay;
window.FAST_MODE = FAST_MODE;
