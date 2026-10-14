# MCP Marketplace + MCP Secure

An MCP server marketplace where every server is scanned **before** it can be listed. A publisher
submits a repository; MCP Secure ingests it at a pinned commit, runs the threat analyzers, applies a
deterministic policy, and the verdict decides the listing: PASS is listed, REVIEW waits for an
admin, FAIL is rejected.

The design is in [spec/PIPELINE_SPEC.md](spec/PIPELINE_SPEC.md). [README-POC.md](README-POC.md)
covers the demo flow and what is real versus simulated.

## Setup

Requires Node.js 20+ and Python 3.9+.

```bash
npm install
npm run seed          # database/marketplace.db: 59 catalog servers, demo users, clients

# Model B (one time): Python venv + TypeScript extractor; first start downloads ~500 MB
cd model_b_service && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt \
  && (cd js && npm install) && cd ..

npm start             # http://localhost:3000 (PORT=xxxx for another port)
```

`npm start` starts the local analyzer services itself if they are not already running: the AST
taint service on :8701 and Model B on :8765. If the Model B venv is missing, the server still
starts, but Model B reports "not running". The policy then refuses to PASS anything (fail-closed),
so every scan ends in REVIEW.

On first start the server also seeds the three demo servers from `demo_servers/`, scans them, and
creates a signing key in `database/mcs_key.json`.

**Demo accounts:** log in with the email `<username>@example.com` and password `password123`.
The usernames are `alice_dev`, `bob_builder`, `charlie_ai`, `dave_sec` and `anthropic_official`.
`dave_sec` is the admin who reviews flagged submissions.

## Commands

| Command | What it does |
|---|---|
| `npm start` | Marketplace, plus the local analyzer services |
| `npm test` | Node tests (ingestion, policy, listing rules, demo regression gate) + the AST analyzer's pytest suite |
| `npm run scan -- <git-url \| demo:<name> \| dir> [--json]` | Headless scan with the production pipeline (evaluation, CI). Exit codes: 0 PASS, 1 FAIL, 2 REVIEW, 3 error |
| `npm run conformance -- --url http://127.0.0.1:8703` | Checks an analyzer service against the contract before it is added to the registry |
| `npm run analyzer:ast` / `npm run analyzer:model-b` | Run one analyzer service by hand |
| `npm run test:e2e` | Playwright end-to-end tests (real marketplace + analyzers, throwaway database). First time: `npx playwright install chromium` |
| `npm run eval:adversarial` | Hand-built evasion cases in `eval/adversarial/`, each with its expected verdict |
| `npm run eval` / `npm run eval:report` | Scan the GitHub-advisory corpus (`eval/corpus.json`) and popular benign servers (`eval/benign.json`), then write `eval/results/<run>.md`. Slow (hours): Model B on CPU |

## How a scan works

```
source (git URL @ commit | uploaded files | demo server)
  → INGEST   src/mcpsecure/ingest/        pin commit, shared file filter, tool discovery (Python ast / TS compiler),
                                          AnalysisBundle + content fingerprint (covers code, tools and listing text)
  → ANALYZE  config/analyzers.json         every registered analyzer, in parallel, over the same bundle
               ast_taint  :8701            Python taint analysis (Mustafa)              REAL
               model_b    :8765            UniXcoder + LoRA, 6 vulnerability classes (Talha)   REAL
               model_a    MODEL_A_URL      tool poisoning / preference manipulation (Talha)    heuristic stand-in until served
               ingest_checks (built-in)    declared tools vs tools found in the code
  → POLICY   src/mcpsecure/policy/ + ruleset.json (policy-v4)   pure, deterministic, hash pinned in every record
  → TRIAGE   model_c  MODEL_C_URL          REVIEW only, advisory, never changes the verdict
  → ATTEST   sign → transparency log → anchor (simulated; blockchain work is deferred)
```

Nothing from a candidate is ever executed: code is parsed, never imported, installed or run.

## Adding an analyzer (Model A, Model C, …)

1. Implement the contract (spec §6): `GET /v1/health` and `POST /v1/analyze` returning findings in
   the shared threat taxonomy (`contracts/threats.json`). For Python services,
   `services/analyzer_kit/analyzer_kit.py` provides the HTTP server and helpers; see
   `ast_taint_analyzer/service.py` for a complete example.
2. `npm run conformance -- --url <your service>` must pass.
3. Point the slot at it, e.g. `MODEL_A_URL=http://127.0.0.1:8703 npm start`. The built-in stand-in
   is replaced automatically, and the UI card, scan record and model hashes follow. No code changes.

## Layout

```
server.js                     Express app
src/db.js                     better-sqlite3 access; database/schema.sql + database/migrations.js
src/routes/                   marketplace API, MCP Secure API (/api/mcs), submission gate (/api/v1)
src/mcpsecure/
  ingest/                     sources (git/files/local), file selection, tool discovery, bundle
  orchestrator/               pipeline, analyzer registry + contract client, local service launcher
  analyzers/builtin/          in-process analyzers (Model A stand-in, declared-vs-discovered check)
  policy/engine.js            policy rule types; rule instances live in ruleset.json
  engine.js, service.js       scan record → sign → log → anchor
  submissions.js, listing.js  submission gate, worker, admin decisions, listing state
contracts/                    JSON Schemas for the bundle and the analyzer contract, threat taxonomy
config/analyzers.json         analyzer registry
services/analyzer_kit/        shared Python helper for contract services
ast_taint_analyzer/           AST taint engine + service.py
model_b_service/              Model B inference + contract endpoints
demo_servers/                 real demo MCP servers (+ _bait/ rug-pull variants)
bin/mcs-scan.js               headless scan CLI
scripts/conformance.js        analyzer contract conformance suite
test/                         Node tests
tests/e2e/                    Playwright end-to-end tests
eval/                         evaluation corpus, adversarial cases, runners, result reports
```

## Not in the repository (on purpose)

| File | Why | How you get it |
|---|---|---|
| `node_modules/` | installed per machine | `npm install` |
| `model_b_service/.venv/` | Python environment | see Setup |
| `database/marketplace.db` | local data, may hold personal accounts | `npm run seed`, then `npm start` |
| `database/mcs_key.json` | private signing key | generated automatically on first `npm start` |
| `eval/results/*.jsonl` | raw per-scan evaluation output (MBs) | `npm run eval`; the `.md` reports are committed |

Each teammate has their own database and signing key, so an attestation signed on one machine
verifies against that machine's public key.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | 3000 | marketplace port |
| `SESSION_SECRET` | random per process | set it in any shared deployment |
| `AST_TAINT_URL` / `MODEL_B_URL` | `http://127.0.0.1:8701` / `:8765` | analyzer services |
| `MODEL_A_URL` / `MODEL_C_URL` | unset | trained Model A / Model C services, once they exist |
| `MCS_SPAWN_ANALYZERS` | on | `0` = do not start local analyzer services |
| `MCS_ALLOW_LOCAL_SOURCES` | on | `0` = refuse local-directory sources (production) |
| `MCS_PYTHON` | `python3` | interpreter for the AST service and Python tool discovery |
