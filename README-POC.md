# MCP Secure — Skeleton POC Layer

## What This Is

This is a **visual, working POC walkthrough** of MCP Secure built on top of the existing MCP Marketplace.
It demonstrates three future security systems as they would operate in production, using:

- **Real cryptography** where appropriate (SHA-256, Ed25519, Merkle proofs)
- **Deterministic heuristics** where future ML models will plug in
- **Simulated chain anchoring** where a real Ethereum tx will anchor the root

Every simulated component is clearly labeled `SIMULATED (POC)` in the UI.
Every real component is labeled `REAL CRYPTO`.

---

## Quick Start

```bash
cd mcp-marketplace
npm start
# → http://localhost:3000
```

The server automatically seeds the three demo servers and pre-runs their scans on every startup.

### Demo Flow (recommended order)

1. **`/scan`** — Select "Shell Runner" → watch pipeline → `FAIL` verdict with detailed evidence
2. **`/scan`** — Select "Weather Tools" → `PASS` → signed attestation issued
3. **`/attestations`** → "Verify a Server" tab → `weather-tools` → all 5 checks pass → **Trusted**
4. **`/watcher`** → click "☠ Bait & Switch" on weather-tools → old PASS **superseded** → new **FAIL**
5. **`/verifier`** → External Marketplace mode → scan `acme-crm-connector` → signed attestation downloaded
6. **`/verifier`** → MCP Endpoint Inspector → see JSON in/out

---

## What Is Real vs. Simulated

| Component | Status | Notes |
|---|---|---|
| SHA-256 fingerprinting | **REAL** | Node.js `crypto.createHash('sha256')` |
| Ed25519 signing | **REAL** | Node.js `crypto.generateKeyPairSync('ed25519')` |
| Ed25519 verification (browser) | **REAL** | Web Crypto API `crypto.subtle.verify('Ed25519')` |
| Merkle tree construction | **REAL** | Pairwise SHA-256, RFC-6962 style |
| Merkle inclusion proofs | **REAL** | Sibling path, verified in browser |
| Transparency log (append-only) | **REAL** | SQL table, monotonic index |
| Signed Tree Head | **REAL** | Ed25519 over `{rootHash, size, timestamp}` |
| AST Taint Analyzer | **REAL** | Python `ast` taint engine (`ast_taint_analyzer/`, Part 2), invoked as a local subprocess. Falls back to the labelled regex heuristic for non-Python servers or when no interpreter is found |
| Model A (text, tool poisoning) | **SIMULATED** | Regex heuristics → future: fine-tuned LoRA text model |
| Model B (code, obfuscation) | **SIMULATED** | Regex heuristics → future: fine-tuned LoRA code model |
| Policy Engine | **REAL** | Pure deterministic function, production-identical |
| Tool implementation source | **REAL** | `tools.source_code` holds the Python the analyzer parses; markdown scraping is now only a fallback for servers seeded before the column existed |
| Scan pipeline stage timings | **REAL** | Streamed over SSE from the backend as each stage completes; durations are measured, never scripted. Timings are deliberately excluded from the ScanRecord so the signed artifact stays byte-identical across runs |
| Model C (triage agent) | **SIMULATED** | Static text → future: autonomous LLM agent with toolset |
| Blockchain anchoring | **SIMULATED** | In-process mock → future: Ethereum Sepolia via ethers.js. Every field is *derived* (block advance and tx hash come from the Merkle root), never random, so the mock preserves the project's determinism property. A real Sepolia tx would not be reproducible this way — block number and tx hash come from the network |
| Watcher commit SHA | **SIMULATED** | SHA-256 of content → future: `git ls-remote` via cron |

---

## Files Added

### Backend
| File | Purpose |
|---|---|
| `src/mcpsecure/crypto.js` | Real SHA-256, Ed25519, Merkle |
| `src/mcpsecure/engine.js` | Deterministic scan engine (3 analyzers + policy) |
| `src/mcpsecure/store.js` | DB wrapper for 5 MCS tables |
| `src/mcpsecure/service.js` | Orchestration: scan → attest → log → anchor |
| `src/mcpsecure/seed.js` | Demo server seeding (idempotent) |
| `src/mcpsecure/ruleset.json` | Policy ruleset (SHA-256 pinned in every ScanRecord) |
| `src/routes/mcpsecure.js` | Express routes at `/api/mcs` |

### Frontend
| File | Purpose |
|---|---|
| `public/scan.html` | Feature 1: Animated pipeline |
| `public/attestations.html` | Feature 2: Attestation/log/chain explorer |
| `public/watcher.html` | Feature 3: Version watcher dashboard |
| `public/verifier.html` | Feature 4: External verifier |
| `public/js/mcpsecure.js` | All frontend logic + real client-side crypto |

### Modified
| File | Change |
|---|---|
| `database/schema.sql` | 5 new `mcs_*` tables appended |
| `server.js` | MCS routes + seed wired in |
| `public/js/components.js` | MCS nav links added to navbar |
| `public/server-detail.html` | 🔒 Security tab added |
| `public/css/styles.css` | ~370 lines of MCS-specific CSS appended |

---

## API Reference

All endpoints at `/api/mcs`:

| Method | Path | Description |
|---|---|---|
| `GET` | `/pubkey` | Ed25519 public key (for client verification) |
| `POST` | `/scan` | Run scan pipeline on a marketplace server |
| `GET` | `/scan/stream?serverSlug=&baitAndSwitch=` | Same scan over SSE — `begin`, `stage`, `result`, `error` events with measured per-stage durations |
| `GET` | `/scans[?serverSlug=]` | List scan records |
| `GET` | `/attestations/:id` | Get single attestation |
| `GET` | `/log` | Transparency log leaves + signed tree head |
| `GET` | `/log/:index/proof` | Merkle inclusion proof |
| `GET` | `/anchors` | Chain anchor receipts |
| `POST` | `/anchors/trigger` | Manual anchor now |
| `GET` | `/watcher` | Watcher rows |
| `POST` | `/watcher/:id/simulate-update` | Simulate docs-only or bait-and-switch |
| `POST` | `/verify-external` | External verifier (Feature 4) |
| `GET` | `/verify-fingerprint?fingerprint=` | Client-side verify lookup |
| `GET` | `/external-requests` | List external verification requests |
| `POST` | `/mcp-endpoint-mock` | MCP inspector JSON in/out |
| `GET` | `/stats` | Scan/log/anchor counts |

---

## Upgrade Path (from POC → Production)

### 1. Replace heuristic analyzers with real ML models

```js
// In src/mcpsecure/engine.js — replace runAstTaint() with:
const { execFile } = require('child_process');
function runAstTaint(code) {
  // Call tree-sitter taint analyzer subprocess
  return execFile('mcs-taint', ['--stdin'], { input: code });
}

// Replace runModelAText() with:
async function runModelAText(text) {
  const resp = await fetch(process.env.MODEL_A_ENDPOINT, {
    method: 'POST', body: JSON.stringify({ text }),
    headers: { Authorization: 'Bearer ' + process.env.MODEL_A_KEY }
  });
  return resp.json(); // { score, evidence, threats }
}
```

### 2. Anchor to Ethereum Sepolia

```js
// In src/mcpsecure/service.js — replace simulateAnchor() with:
const { ethers } = require('ethers');
async function anchorToSepolia(rootHash) {
  const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
  const wallet = new ethers.Wallet(process.env.ANCHOR_PRIVATE_KEY, provider);
  const tx = await wallet.sendTransaction({
    to: process.env.ANCHOR_CONTRACT_ADDRESS,
    data: ethers.hexlify(ethers.toUtf8Bytes('MCS:' + rootHash)),
  });
  await tx.wait();
  return { txHash: tx.hash, blockNumber: tx.blockNumber };
}
```

### 3. Real git commit tracking for watcher

```bash
# cron every 5 minutes
git ls-remote <repo_url> HEAD | awk '{ print $1 }'
# → compare with mcs_watcher_rows.last_seen_sha
# → if changed: fetch content, recompute fingerprint, re-scan if changed
```

### 4. Real MCP transport for Feature 4

```js
// Expose verify_mcp_server as a real MCP tool using @modelcontextprotocol/sdk
const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const mcsServer = new Server({ name: 'mcp-secure-verifier', version: '1.0.0' });
mcsServer.setRequestHandler(CallToolRequestSchema, async (req) => {
  if (req.params.name === 'verify_mcp_server') {
    const result = await runFullPipeline(req.params.arguments.candidate_ref);
    return { content: [{ type: 'text', text: JSON.stringify(result) }] };
  }
});
```

---

## Security Notes

- The Ed25519 keypair is generated once at startup and stored in `database/mcs_key.json`. **Keep this file secret in production.**
- In production, rotate the keypair on a schedule and publish key rotation events to the transparency log.
- The transparency log is append-only by design. In production, enforce this at the DB level with triggers or use a dedicated log service (e.g., Trillian).

---

## Known Limitations (POC only)

- No real ML inference — all analyzer scores are heuristic
- No real Ethereum transactions — chain anchoring is in-process simulation
- No real git polling — watcher commits are SHA-256 deterministic mocks
- No real MCP transport for Feature 4 — the MCP endpoint inspector is a mock JSON display
- Ed25519 client-side verification requires a browser that supports `crypto.subtle.verify('Ed25519')` — Chrome 113+, Firefox 115+

---

_Built as part of the MCP-SecureCreate FYP project. All real crypto operations use Node.js built-in `crypto` module (server) and Web Crypto API (browser) — no external crypto libraries required._
