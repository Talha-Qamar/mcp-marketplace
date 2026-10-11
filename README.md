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

`src/mcpsecure/engine.js` runs three analyzers. The **AST taint analyzer is real**: `runAstTaint()`
delegates via `src/mcpsecure/astTaint.js` to the Python engine in `ast_taint_analyzer/` (Part 2),
which is invoked as a local subprocess — offline, deterministic, and it never executes the code it
parses. Severity tiers map to the 0-1 policy score through `astSeverityScores` in `ruleset.json`
(high → 1.0 hard-fail, medium → 0.55 review, low → 0.25). Candidates with no analysable Python
fall back to the legacy regex heuristic, which is labelled `SIMULATED` in the evidence so the UI
never overstates what ran.

Model A (tool-description poisoning) and Model B (code vulnerabilities) are still regex heuristics.
The trained models replace these; Model B returns a 0-1 score plus evidence lines, with review/fail
thresholds 0.40/0.75 from `ruleset.json`, and consumes the AST analyzer's 16-feature vector
(`python -m ast_taint feature-names`) as a frozen contract.

The AST analyzer needs Python 3.9+ on `PATH` (or set `MCS_PYTHON` to an interpreter). No `pip
install` is required — the bridge puts `ast_taint_analyzer/src` on `PYTHONPATH` itself.

## Known POC shortcuts

- `server.js` uses a hard-coded session secret. Move it to an environment variable before any
  deployment.
