# MCP Marketplace + MCP Secure POC

Local replica of an MCP server marketplace (UI + Express backend) with the **MCP Secure** security
layer: scanning pipeline, policy engine, Ed25519-signed attestations, transparency log and watcher.
Part of the FYP *MCP Secure*. See [README-POC.md](README-POC.md) for the security layer in detail
(what is real vs. simulated, demo flow).

## Setup

Requires Node.js 18+.

```bash
npm install        # dependencies
npm run seed       # builds database/marketplace.db (59 marketplace servers, demo users, clients)
npm start          # http://localhost:3000  (PORT=xxxx npm start for another port)
```

On first start the server also adds the three MCP Secure demo servers, pre-runs their scans and
creates a fresh signing key in `database/mcs_key.json`.

Demo accounts created by the seed: `alice_dev`, `bob_builder`, `charlie_ai`, `dave_sec`,
`anthropic_official`. **Log in with the email, not the username** — the seed sets each one to
`<username>@example.com` (e.g. `alice_dev@example.com`), and the login route looks users up by
email. Password for all five is `password123` (local testing only).

## Not in the repository (on purpose)

| File | Why | How you get it |
|---|---|---|
| `node_modules/` | installed per machine | `npm install` |
| `database/marketplace.db` | local data, may hold personal accounts | `npm run seed`, then `npm start` |
| `database/mcs_key.json` | private signing key | generated automatically on first `npm start` |

Each teammate therefore has their own database and signing key; attestations signed on one
machine verify against that machine's public key.

## Layout

```
server.js                 Express app, routes, session setup
src/db.js                 sql.js database access
src/routes/               marketplace + MCP Secure HTTP routes
src/middleware/           auth helpers
src/mcpsecure/            MCP Secure: engine.js (scan pipeline + analyzers), ruleset.json (policy),
                          crypto.js (SHA-256 / Ed25519 / Merkle), store.js (persistence)
public/                   HTML/CSS/JS front end (/, /servers, /scan, /attestations, /watcher, /verifier, ...)
database/schema.sql       schema; database/seed.js + database/data/ seed data
generate_*.py, scripts/   scripts used to produce the seed data
```

## Where the models plug in

`src/mcpsecure/engine.js` runs three analyzers and a policy engine. Review and fail thresholds are
0.40 and 0.75, from `ruleset.json`.

| Analyzer | Status |
|---|---|
| **AST taint** | **Real.** `runAstTaint()` delegates via `src/mcpsecure/astTaint.js` to the Python engine in `ast_taint_analyzer/` (Part 2), a local subprocess: offline, deterministic, never executes the code. Severity → score via `astSeverityScores` (high 1.0 hard-fail, medium 0.55 review, low 0.25). Non-Python candidates fall back to the regex heuristic, labelled `SIMULATED` in the evidence. |
| **Model B** (code vulnerabilities) | **Real** when `MODEL_B_URL` is set. The trained classifier (`model_b_service/`, see its README and `MODEL_CARD.md`) scores every function of the tools' source and the GitHub repo for six classes. |
| Model A (tool poisoning / PMA) | Regex heuristic for now. |

**How Model B and the AST analyzer combine** (`modelBPolicy` in `ruleset.json`): Model B reads one
function at a time and cannot see whether tool input reaches the risky call, so on its own it can
send a server to REVIEW but never FAIL it. A Model B finding keeps its full score, and can FAIL the
server, only when the AST analyzer reports a medium/high taint flow of the matching category in the
same function (shell → command injection, exec/dynamic → code injection, file → path traversal,
deserialize → unsafe deserialization). Without corroboration a fail-level Model B score counts as
0.55 (REVIEW) and a review-level one as 0.25 (evidence only). Model B does not consume the AST
feature vector; the two are combined here, at the policy layer.

To use the real Model B, start the service and run the marketplace with `MODEL_B_URL`:

```bash
cd model_b_service && pip install -r requirements.txt && (cd js && npm install)
python serve.py --port 8765                  # first start downloads the base model (~500 MB)
cd .. && MODEL_B_URL=http://127.0.0.1:8765 npm start
```

- Without `MODEL_B_URL`, the old Model B heuristic runs and the analyzer card says `simulated`.
- If the service is configured but down, Model B scores 0.40 and the scan goes to REVIEW.
- The AST analyzer needs Python 3.9+ on `PATH` (or set `MCS_PYTHON`). No `pip install` is needed:
  the bridge puts `ast_taint_analyzer/src` on `PYTHONPATH` itself.

## Known POC shortcuts

- `server.js` uses a hard-coded session secret. Move it to an environment variable before any
  deployment.
