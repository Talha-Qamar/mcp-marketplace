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

`src/mcpsecure/engine.js` currently uses regex heuristics for the AST taint analyzer, Model A
(tool-description poisoning) and Model B (code vulnerabilities). The trained models replace these;
Model B returns a 0-1 score plus evidence lines, with review/fail thresholds 0.40/0.75 from
`ruleset.json`.

## Known POC shortcuts

- `server.js` uses a hard-coded session secret. Move it to an environment variable before any
  deployment.
