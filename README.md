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
`anthropic_official`, all with password `password123` (local testing only).

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
| **Model B** (code vulnerabilities) | **Real.** The trained classifier runs as a local service in `model_b_service/` (see its README and `MODEL_CARD.md`). |
| AST taint | Regex heuristic for now; the teammate's analyzer replaces it. |
| Model A (tool poisoning / PMA) | Regex heuristic for now. |

To use the real Model B, start the service and run the marketplace with `MODEL_B_URL`:

```bash
cd model_b_service && pip install -r requirements.txt && (cd js && npm install)
python serve.py --port 8765                  # first start downloads the base model (~500 MB)
cd .. && MODEL_B_URL=http://127.0.0.1:8765 npm start
```

- Without `MODEL_B_URL`, the old Model B heuristic runs, and scan records say `modelBMode: "simulated"`.
- If the service is configured but down, scans go to REVIEW.

## Known POC shortcuts

- `server.js` uses a hard-coded session secret. Move it to an environment variable before any
  deployment.
