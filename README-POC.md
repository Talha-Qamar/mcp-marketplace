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

1. **`/scan`**: select "Shell Runner", watch the live pipeline, get `FAIL` with file:line evidence.
2. **`/scan`**: select "Weather Tools", get `PASS` and a signed attestation.
3. **`/publish`** (log in as `alice_dev@example.com`): pick a preset, or paste a public GitHub repo.
   The submission is scanned and the listing appears only if the verdict allows it.
4. **`/admin`** → Review queue (log in as `dave_sec@example.com`): approve or reject a REVIEW
   submission. A note is required, and the decision is saved.
5. **`/attestations`** → "Verify a Server" tab → `weather-tools`: all checks pass, **Trusted**.
6. **`/watcher`**:
   - "Docs only" re-ingests with a README change; the fingerprint is unchanged, so there is no re-scan.
   - "☠ Bait & Switch" swaps in the rug-pull code. The fingerprint changes, the server is re-scanned
     and gets `FAIL`, and the listing is suspended.
7. **`/verifier`** → External Marketplace mode: scan a real public repo (the official fetch server).
   The candidate is never onboarded.

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
| AST Taint Analyzer | **REAL** | Python `ast` taint engine (`ast_taint_analyzer/`, Part 2) served over the analyzer contract (`service.py`, :8701). Analyses the tool handlers that ingestion discovered |
| Model A (text, tool poisoning / preference manipulation) | **HEURISTIC STAND-IN** | Built-in regex analyzer behind the same contract, labelled in the UI. Replaced by setting `MODEL_A_URL` once the trained model is served |
| Model B (code vulnerabilities) | **REAL** | Trained Model B v8.2 (UniXcoder + LoRA, 6 classes) served over the contract (`model_b_service/serve.py`, :8765). FAIL only with AST corroboration (ruleset `model_b_requires_corroboration`). If it is not running the slot reports so and nothing can PASS |
| Policy Engine | **REAL** | Pure deterministic function (policy-v4): rule types in `src/mcpsecure/policy/engine.js`, rule instances in `ruleset.json`. No PASS without coverage |
| Submission gate | **REAL** | `/api/v1/submissions`: hidden listing → scan → approved / in review / rejected; admin decisions stored with a note |
| Ingestion | **REAL** | Git repos cloned at a pinned commit (real SHA), uploads, or the bundled demo servers. One file filter; static tool discovery for Python (decorators, low-level `Tool(...)`) and TypeScript (`server.tool`, `registerTool`, low-level handlers). Nothing is executed |
| Scan pipeline stage timings | **REAL** | Streamed over SSE from the backend as each stage completes; durations are measured, never scripted. Timings are deliberately excluded from the ScanRecord so the signed artifact stays byte-identical across runs |
| Model C (verification agent) | **NOT BUILT YET** | Registry slot ready (`MODEL_C_URL`). Advisory only, runs on REVIEW; the admin decides |
| Blockchain anchoring | **SIMULATED** | In-process mock → future: Ethereum Sepolia via ethers.js. Every field is *derived* (block advance and tx hash come from the Merkle root), never random, so the mock preserves the project's determinism property. A real Sepolia tx would not be reproducible this way — block number and tx hash come from the network |
| Watcher | **PARTLY REAL** | Fingerprints are real and cover code, so a code swap is detected and a docs-only change is not. Polling a remote repo for new commits (`git ls-remote`) is not built yet; updates are triggered from the demo buttons |

---

## Files Added

### Backend
| File | Purpose |
|---|---|
| `src/mcpsecure/crypto.js` | Real SHA-256, Ed25519, Merkle |
| `src/mcpsecure/engine.js` | Builds the ScanRecord from the orchestrator (`src/mcpsecure/orchestrator/`) |
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

### 1. Plug in the remaining models

Analyzers are services behind one contract (spec §6), so nothing in the engine changes. Implement
`/v1/health` + `/v1/analyze`, pass `npm run conformance -- --url <service>`, then set `MODEL_A_URL`
(or `MODEL_C_URL`). See README.md → "Adding an analyzer".

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
