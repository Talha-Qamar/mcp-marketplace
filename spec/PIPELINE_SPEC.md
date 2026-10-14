# MCP Secure — Detection Pipeline Specification

| | |
|---|---|
| Status | **Phase 1 implemented** on `feat/pipeline-spec` (2026-10-12). Appendix B lists what was built and where it differs from this text. §8 (blockchain) is deferred. |
| Base | `feat/model-b-v8` (PR #2: Model B v8.2 + AST taint analyzer + policy-v3) |
| Scope | Ingestion → analyzers → policy → attestation, the analyzer plug-in contract, and the marketplace submission gate. Blockchain anchoring and the external MCP Secure server are specified only as far as this design must leave room for them. |
| Owners (slide 9) | **Muhammad**: ingestion pipeline, blockchain pipeline, MCP Secure server. **Talha**: Model B, Model A, Model C, model API endpoints, evaluation. **Mustafa**: AST taint analyzer, policy engine, integrated verdict, verification pipeline. |

Section 16 lists the design decisions. D2–D8 were decided on 2026-10-12; D1 is deferred with the blockchain work.

---

## 1. Goals and non-negotiables

From the proposal defence:

1. **Pre-publication gate.** No server is listed in the marketplace until the pipeline has issued a verdict and that verdict allows it (PASS, or REVIEW plus an admin approval).
2. **Three threats** (slide 3): command injection, tool poisoning and preference manipulation. Model B also covers path traversal, SSRF, code injection, SQL injection and unsafe deserialization, so the taxonomy (§6.3) includes them.
3. **Offline and deterministic.** The same input, ruleset and analyzer artifacts produce the same findings and the same verdict, byte for byte. No cloud LLM sits in the verdict path.
4. **Static.** Candidate code is parsed, never imported, installed or executed.
5. **Verifiable.** Every decision is signed (Ed25519), appended to the Merkle transparency log, and later anchored on-chain. A third party can check a verdict without trusting the marketplace's database.
6. **Pluggable.** Adding Model A, Model C or a future analyzer means deploying a service that implements §6 and adding one registry entry. The orchestrator, policy code and UI do not change.

Additional rule, new in this spec: **no PASS without coverage.** If the code analyzers could not actually analyse the server (an unsupported language, no source, a service down), the result is REVIEW with a stated reason, never PASS. Today a Rust or Go server can PASS because only a regex runs over its markdown.

---

## 2. Architecture

```
                         ┌────────────────────────── Marketplace (Node/Express) ──────────────────────────┐
 publisher ──submit──▶   │  Submissions API ─▶ Job queue ─▶ ORCHESTRATOR                                   │
 (git URL / upload)      │                                   │                                             │
                         │   1 INGEST ──────────────────────▶│ AnalysisBundle (+ content fingerprint)       │
                         │   2 ANALYZE  (parallel, HTTP) ────┼──▶ AST taint service   (Mustafa)  :8701     │
                         │                                   ├──▶ Model B service     (Talha)    :8702     │
                         │                                   ├──▶ Model A service     (Talha)    :8703     │
                         │   3 POLICY  (pure, ruleset.json)  │                                             │
                         │   4 TRIAGE  (REVIEW only) ────────┴──▶ Model C service     (Talha)    :8704     │
                         │   5 ATTEST  sign ─▶ transparency log ─▶ anchor (simulated → Sepolia)            │
                         │                                                                                 │
                         │  Catalog · Admin review queue · Watcher · Public verify endpoints               │
                         └─────────────────────────────────────────────────────────────────────────────────┘
                                         ▲
 external agent / marketplace ─MCP─▶ MCP Secure Server (thin adapter, Final 2) ─HTTP─▶ /api/v1/verify
```

- **One orchestrator, two callers.** The marketplace publish flow and the external MCP Secure server (slide 7) both run the same pipeline code, with the same signing key and the same log. The MCP Secure server does not get its own copy of the pipeline.
- **Analyzers are services** behind one HTTP contract (§6), so each owner can build, test and deploy their own service independently. Model B already works this way (*exists*, `model_b_service/serve.py`). The AST analyzer currently runs as a blocking subprocess (*exists*, `src/mcpsecure/astTaint.js`) and gets a service wrapper.
- **The orchestrator stays in Node.** The crypto, Merkle log, store and browser-side verification already exist there and work. Rewriting them would cost time and add nothing.

---

## 3. Pipeline stages

| # | Stage | Input → output | Deterministic | Owner |
|---|---|---|---|---|
| 1 | Ingest | source ref → `AnalysisBundle` + `content_fingerprint` | yes, given a commit SHA | Muhammad |
| 2 | Analyze | bundle → one `AnalyzerResult` per registered analyzer | yes (contract requirement) | each analyzer owner |
| 3 | Policy | results + ruleset → `PolicyResult` (verdict, reasons, effective scores) | yes (pure function) | Mustafa |
| 4 | Triage | REVIEW only: bundle + findings → advisory recommendation | recorded, not in the verdict path (D2) | Talha |
| 5 | Attest | everything above → signed attestation, log leaf, later an anchor | signature yes; `issued_at` is the only wall-clock field | Muhammad |

Stages 1–3 are the reproducible core. Each stage reports progress events (§10) for the live UI. Timings never go into a signed artifact.

---

## 4. Ingestion (Mid 1: Muhammad)

Ingestion is the only stage that touches the outside world. Its job is to turn "a server" into one immutable bundle that every analyzer reads. Today each analyzer gathers its own input: the AST bridge scrapes markdown and Model B clones GitHub by itself. That stops.

### 4.1 Source kinds

| Kind | Input | Pinning | Use |
|---|---|---|---|
| `git` | `repo_url` (https, public) + `ref` (branch, tag or SHA) | `ref` is resolved to a full commit SHA via `git ls-remote` **before** cloning; the SHA goes into the bundle | publishing, watcher re-scans, external verify |
| `upload` | `.zip` / `.tar.gz` or a file list | `commit_sha: null`; the source is identified by the archive's SHA-256 | publishers without a public repo |
| `local` | directory path | `commit_sha` from `git rev-parse` if it is a repo | demo servers, evaluation, tests. **Disabled in production.** |

Remote-only servers (a hosted URL with no source, e.g. `https://mcp.asana.com/v2/mcp`) are out of scope for Mid 1; see D3.

### 4.2 Safety rules (hostile input)

- **Never execute anything from the candidate.** No `npm install`, `pip install`, imports, builds or hooks. `git clone` does not run repository hooks; keep it that way.
- **Source validation:**
  - only https URLs on allowed git hosts (`MCS_GIT_HOSTS`, default github.com, gitlab.com, bitbucket.org, codeberg.org): no internal hosts, IP literals or metadata endpoints (SSRF);
  - refs may not start with `-` or contain `..` (no git option injection), and `ls-remote` gets `--` before the URL;
  - `/tree/<ref>/<subdir>` paths may not contain `.` or `..` segments.
- **git hardening:**
  - https only, no credentials (`GIT_TERMINAL_PROMPT=0`, empty credential helper);
  - `--depth 1`, `--no-recurse-submodules`, `GIT_LFS_SKIP_SMUDGE=1`, `-c core.symlinks=false`;
  - timeout of 120 s; abort if the checkout exceeds 200 MB.
- **Never follow symlinks.** Skip them, and record each one as a coverage note. A symlink to `/etc/passwd` inside a repo must not be read.
- **Archive extraction:** reject absolute paths and `..` (zip-slip), cap the entry count and the uncompressed size.
- **Work in a fresh temp directory** per job and delete it afterwards.

### 4.3 File selection

There is one filter for the whole pipeline. Today AST and Model B use two different skip lists (`ast_taint/config.py` `SKIP_DIR_NAMES` and `model_b.py` `SKIP_DIR`). Analyzers analyse what they receive; they do not re-filter.

*Revised after adversarial testing (Appendix C).* The skipped directories below are split in two:

- **Vendor directories** (`node_modules`, `.git`, `venv`, caches) are never read.
- **Deferred directories** (tests, examples, docs, `dist`, `build`) are held back, not dropped. A deferred file is admitted when it is a package entrypoint (`package.json` main/module/bin/exports, pyproject `[project.scripts]`) or is imported, transitively, by admitted code (`src/mcpsecure/ingest/reachable.js`). Otherwise runtime code could hide in `examples/`, or ship as a committed `dist/` bundle that differs from the reviewed `src/`.
- A code file skipped for a size or count limit is listed in `coverage.skipped_code`, and the policy refuses PASS.

- **Code:** `.py .ts .tsx .js .mjs .cjs`.
- **Metadata files:** `README*`, `package.json`, `pyproject.toml`, `requirements*.txt`, `server.json` (MCP registry manifest), `smithery.yaml`, `Dockerfile`.
- **Skipped directories:** `node_modules dist build out .git vendor venv .venv site-packages __pycache__ tests __tests__ spec e2e examples docs fixtures coverage .next`. These are Model B's evaluation-corpus filters, so the model sees the same kind of input it was evaluated on.
- **Skipped files:** `*.d.ts *.min.js *.test.* *.spec.* *_test.py test_*.py conftest.py setup.py`.
- **Limits:** 400 KB per file, 5,000 files, 20 MB of bundle content in total. Anything over a limit is dropped and recorded in `bundle.coverage.notes`, never silently.

### 4.4 Tool discovery

Analyzers need to know which functions are MCP tools. Tool parameters are the taint sources, tool descriptions are what Model A reads, and a finding inside a tool handler matters more than one in an unused helper.

| Language | Patterns recognised (static only) |
|---|---|
| Python | decorators whose last segment is in the AST analyzer's `TOOL_DECORATORS` (`@mcp.tool()`, `@server.tool`, `@tool`, …). Name comes from the `name=` kwarg, else the function name. Description comes from the `description=` kwarg, else the docstring. Also low-level SDK servers: `Tool(name=…, description=…, inputSchema=…)` literals returned from a `@server.list_tools()` function, with handlers found through the `@server.call_tool()` dispatch. |
| TS/JS | `server.tool(name, [description], schema, handler)`, `server.registerTool(name, {title, description, inputSchema}, handler)`, and `setRequestHandler(ListToolsRequestSchema, …)` returning literal tool arrays, with handlers through the `CallToolRequestSchema` switch/if on `name`. |

Rules:

- A description built at runtime (concatenation of non-literals, read from a file) is recorded with `description_resolved: false` and counts against coverage.
- **Declared vs discovered.** The publisher's form lists tools. If a declared tool is not found in the code, or a discovered tool was not declared, ingestion emits a `metadata_mismatch` finding (analyzer `ingest`). A server that shows one description in the catalog and ships another is a tool-poisoning signal in its own right.
- If no tools are discovered at all, analyzers fall back to all functions (the AST analyzer's `--all-functions` mode) and `coverage.tool_discovery = "none"` is set. Policy treats this as reduced coverage.
- Implementation: Node, in `src/mcpsecure/ingest/`. TS/JS uses the `typescript` npm package in-process (the same compiler Model B's extractor uses). Python uses a small stdlib-only script run with async `spawn`; it only parses.

### 4.5 `AnalysisBundle` (contract)

```jsonc
{
  "bundle_version": "1",
  "content_fingerprint": "sha256:…",        // §4.6
  "server": { "name": "Weather Tools", "description": "…", "declared_language": "python" },
  "source": {
    "kind": "git",
    "repo_url": "https://github.com/acme/weather-mcp",
    "ref": "main",
    "commit_sha": "3f9c…(40 hex)",           // null for uploads
    "archive_sha256": null
  },
  "files": [                                  // sorted by path
    { "path": "src/server.py", "language": "python", "sha256": "…", "size": 1834, "content": "…" }
  ],
  "metadata_files": [ { "path": "README.md", "sha256": "…", "content": "…" } ],
  "tools": [                                  // sorted by (file, start_line)
    {
      "tool_id": "src/server.py#get_forecast",
      "name": "get_forecast",
      "description": "Get the forecast for a city.",
      "description_resolved": true,
      "input_schema": { "type": "object", "properties": { "city": { "type": "string", "description": "…" } } },
      "language": "python",
      "file": "src/server.py",
      "handler": { "name": "get_forecast", "start_line": 12, "end_line": 30 },   // includes decorators
      "discovered_by": "python:decorator"
    }
  ],
  "declared_tools": [ { "name": "get_forecast", "description": "…" } ],
  "coverage": { "tool_discovery": "full|partial|none", "notes": ["skipped 2 symlinks", "…"] }
}
```

Line numbers are always relative to the real file. Today AST evidence reports lines in a blob built by joining every tool's source together.

### 4.6 Content fingerprint

`content_fingerprint = sha256(JCS({bundle_version, server:{name, description}, files:[{path, sha256}], tools:[{name, description, input_schema, file, handler}]}))`

- JCS means RFC 8785 canonical JSON (§8.1).
- **The fingerprint covers the code.** Today's fingerprint (`src/mcpsecure/engine.js:508`) hashes only names and descriptions. A rug pull that swaps only code keeps the same fingerprint, so the watcher cannot see it.
- Commit SHA and repo URL are not part of the fingerprint; they go in the attestation `subject`. Identical content at two commits is the same content.

---

## 5. Orchestrator

- **Registry:** `config/analyzers.json` holds operational settings (URLs, timeouts, enabled flags). It is not hashed into attestations; what an analyzer *is* comes from its `/v1/health` identity, and that is recorded per scan.

  ```jsonc
  {
    "analyzers": [
      { "id": "ast_taint", "url": "${AST_TAINT_URL}", "stage": "analyze", "required": true,  "timeout_ms": 60000 },
      { "id": "model_b",   "url": "${MODEL_B_URL}",   "stage": "analyze", "required": true,  "timeout_ms": 600000 },
      { "id": "model_a",   "url": "${MODEL_A_URL}",   "stage": "analyze", "required": true,  "timeout_ms": 120000,
        "fallback": "builtin:text_heuristic" },
      { "id": "model_c",   "url": "${MODEL_C_URL}",   "stage": "triage",  "required": false, "when": "verdict == REVIEW" }
    ]
  }
  ```

- **Run:** analyze-stage analyzers run in parallel. Each call is retried once on a connection error. An analyzer that still fails gets `status: "error"`; the policy then decides (fail-closed: a required analyzer in error never produces PASS).
- **Fallback analyzers:** an analyzer that is not built yet (Model A today) is served by a **built-in** implementation of the same contract. The current regex heuristic is moved behind the interface with `engine: "heuristic"`. The UI badge reads `engine` from the result, so labelling stays honest. When Talha's service is up, setting `MODEL_A_URL` replaces it.
- **Headless:** the orchestrator has no Express or marketplace-DB dependency. It takes a source ref and returns a scan result. The marketplace, the evaluation CLI (§13) and the MCP Secure server (§12) all call it.

---

## 6. Analyzer contract (all analyzer owners)

Every analyzer, built-in or remote, implements this. JSON Schemas live in `contracts/`, and a conformance suite (§6.5) checks implementations against them.

### 6.1 `GET /v1/health`

```jsonc
{
  "id": "model_b",
  "display_name": "Model B — code classifier",
  "description": "UniXcoder + LoRA, six vulnerability classes",
  "version": "8.2.0",
  "artifact_hash": "sha256:3276ec25…",       // weights + config for models; config.py hash for AST
  "engine": "model",                          // model | static | heuristic | agent
  "consumes": ["files", "tools"],             // bundle fields it reads
  "languages": ["python", "typescript", "javascript"],
  "threats": ["command_injection", "path_traversal", "ssrf", "code_injection", "sql_injection", "unsafe_deserialization"],
  "contract_version": "1"
}
```

The UI builds analyzer cards from this response instead of the hard-coded map in `public/js/mcpsecure.js:531`.

### 6.2 `POST /v1/analyze`

The request is `{ "bundle": AnalysisBundle, "context": { "findings": [...] } }`. `context` is only sent to triage-stage analyzers.

```jsonc
{
  "analyzer": { "id": "ast_taint", "version": "0.1.0", "artifact_hash": "sha256:6352f0…", "engine": "static" },
  "status": "ok",                       // ok | partial | not_applicable | error
  "coverage": { "units_total": 4, "units_analyzed": 4, "languages": ["python"], "notes": [] },
  "findings": [
    {
      "finding_id": "sha256:…",         // hash of (analyzer id, rule, file, line, threat): stable across runs
      "threat": "command_injection",     // §6.3
      "cwe": "CWE-78",
      "score": 1.0,                      // 0–1 on the marketplace scale (review 0.40, fail 0.75)
      "severity": "high",                // low | medium | high
      "location": {
        "file": "src/server.py", "line": 5,
        "function": { "name": "run_command", "start_line": 3, "end_line": 7 },
        "tool_id": "src/server.py#run_command"     // null if not inside a tool handler
      },
      "summary": "tainted 'query' reaches os.system() in 1 hop",
      "details": { "sink": "os.system", "path": ["query"], "n_hops": 1, "sanitized": false }  // analyzer-specific
    }
  ]
}
```

Rules:

- `findings` is sorted by `(file, line, threat, finding_id)`. With the same bundle, the response is byte-identical apart from `seconds`, if present.
- An analyzer with nothing to analyse (Model A on a server with no descriptions, the AST analyzer on a TS-only server) returns `not_applicable`, not `ok` with zero findings. That is what lets the policy enforce "no PASS without coverage".
- `score` and `severity` are both required. Models derive severity from their calibrated score bands. Deterministic analyzers derive score from severity using their own documented table. The policy may override either through the ruleset.
- Findings carry a **function span** (`start_line`/`end_line`). Cross-analyzer corroboration matches on *same file + overlapping function span + same threat*. Today it matches function names only (`engine.js` `fuseModelB`), which mixes up functions with the same name in different files. It also has to translate AST categories to Model B classes inside the policy; with a shared taxonomy, that translation goes away.

### 6.3 Threat taxonomy (`contracts/threats.json`)

| id | CWE | Primary analyzer(s) |
|---|---|---|
| `command_injection` | CWE-78 | AST taint, Model B |
| `code_injection` | CWE-94 | AST taint (exec/dynamic sinks), Model B |
| `path_traversal` | CWE-22 | AST taint (file sinks), Model B |
| `unsafe_deserialization` | CWE-502 | AST taint, Model B |
| `ssrf` | CWE-918 | Model B |
| `sql_injection` | CWE-89 | Model B |
| `tool_poisoning` | — | Model A |
| `preference_manipulation` | — | Model A |
| `metadata_mismatch` | — | ingestion (§4.4) |

Naming fix: the code calls PMA "Prompt Manipulation Attacks" (`engine.js`), but the proposal uses **Preference Manipulation** (MPMA, slide 3). Use `preference_manipulation` everywhere.

AST categories map onto the taxonomy **inside the AST service**: `shell→command_injection`, `exec|dynamic→code_injection`, `file→path_traversal`, `deserialize→unsafe_deserialization`. The original category stays in `details.category`.

### 6.4 Per-analyzer notes

- **AST taint (Mustafa).** Wrap the existing package in a stdlib HTTP service. It analyses `bundle.tools[].handler` spans, so tool parameters are the taint sources, and uses `--all-functions` only when discovery found nothing. The `--json` CLI and the frozen 16-feature vector stay as they are.
- **Model B (Talha).** Add `/v1/health` and `/v1/analyze` beside the existing `/scan`; `/scan` keeps working. It scores every function in `bundle.files`; findings inside a tool handler carry `tool_id`, so the policy can weight them. The service no longer clones GitHub itself; ingestion does that.
- **Model A (Talha, Final 1).** It reads `server.description`, `tools[].name`, `tools[].description`, property descriptions inside `tools[].input_schema`, and optionally the README. Findings point at a tool: `location.tool_id` is set, and `location.file`/`line` give where the description is defined. Until it exists, the built-in heuristic answers under the same id with `engine: "heuristic"`.
- **Model C (Talha, Final 1).** It is a **triage** analyzer, not a detector. It runs only when the verdict is REVIEW, gets `context.findings`, and returns `{recommendation: approve|reject|uncertain, rationale, cited_finding_ids}`. It is stored with the scan and shown to the admin, but it **never changes the verdict** (D2).

### 6.5 Conformance suite

`node scripts/conformance.js --url http://127.0.0.1:8703` must pass before an analyzer is added to the registry. It checks:

1. Health and analyze responses validate against the schemas.
2. The same bundle analysed twice gives byte-identical results (determinism).
3. Golden bundles in `contracts/fixtures/` give the expected `status`. There are four: clean Python, vulnerable Python, poisoned description, TS-only.
4. Empty, oversize and unsupported-language bundles return a contract status, not a 500 error.

A small Python helper (`services/analyzer_kit/`: stdlib HTTP server, request validation, a determinism-settings helper) means each Python analyzer only implements `health()` and `analyze(bundle)`.

---

## 7. Policy engine (Final 1: Mustafa)

A pure function `decide(results, ruleset) → PolicyResult`. Its file hash and `policy_version` go into every attestation (*exists* in principle; generalised here).

```jsonc
// PolicyResult
{
  "verdict": "FAIL",
  "reasons": [ { "rule": "ast_high_hard_fail", "finding_ids": ["sha256:…"] } ],
  "effective_findings": [ { "finding_id": "…", "raw_score": 0.99, "effective_score": 0.55, "rule": "model_b_requires_corroboration" } ],
  "coverage": { "code": "full", "text": "full" }
}
```

The current policy-v3 behaviour, expressed as rule types the engine has to support:

| Rule type | Current instance |
|---|---|
| `hard_fail` | AST finding with severity `high` and not sanitized → FAIL |
| `cap_unless_corroborated` | a Model B finding ≥ 0.75 is capped at 0.55, and one in 0.40–0.75 at 0.25, unless an AST finding with the same threat in an overlapping function has severity medium or high |
| `require_coverage` (new) | a required analyzer in `error` → REVIEW; no code analyzer `ok` on any file → REVIEW "insufficient code coverage"; `tool_discovery = none` → at most REVIEW |
| `threshold` | max effective score ≥ 0.75 → FAIL, ≥ 0.40 → REVIEW, else PASS |
| `require_complete_source` (v5) | any code file skipped for size/count limits → REVIEW |
| `require_resolved_descriptions` (v5) | any tool description built at runtime → REVIEW (Model A could not read it) |
| `require_pinned_artifacts` | an analyzer whose artifact hash differs from `ruleset.analyzerPins` → REVIEW |

Rule *types* live in code; rule *instances* live in `ruleset.json`. Tuning a threshold is then a ruleset change with a new hash, not a code change. **Regression gate:** policy-v4 must reproduce policy-v3's verdicts on all six demo scans before it replaces v3. The Model B card's simulation over `test_mcp_new` and the 46 wild servers becomes a second regression set once the evaluation CLI exists.

`reasons` are stored and shown. The admin review queue currently reads a `policyResult` field that does not exist (`public/admin.html:166`), so every card shows 0%.

---

## 8. Attestation, log and anchoring (Muhammad: blockchain pipeline)

> **DEFERRED: not part of Phase 1.** Until the team takes this up, the existing signing, log and simulated anchor stay exactly as they are (PASS is signed and logged; FAIL and REVIEW are stored unsigned). Phase 1 only has to *store* what this section will need later: the real commit SHA, the code-covering fingerprint, analyzer identities and hashes, findings, and admin decisions. The design below is kept as a proposal.

### 8.1 Canonical JSON

Everything that is hashed or signed is serialised with **JCS (RFC 8785)**. Today `canonicalize()` (`src/mcpsecure/crypto.js:37`) sorts only top-level keys, and signatures are computed over `JSON.stringify(scanRecord)` (`service.js:20`). Browser verification only works because insertion order happens to survive the database round trip, and a third party in another language could not reproduce the bytes.

### 8.2 Attestation format (v2)

```jsonc
// payload (JCS-serialised, then signed)
{
  "type": "https://mcp-secure.dev/attestation/scan/v2",
  "subject": { "repo_url": "…", "commit_sha": "…", "content_fingerprint": "sha256:…", "server_name": "…" },
  "pipeline": {
    "pipeline_version": "1.0.0", "policy_version": "policy-v4", "ruleset_hash": "sha256:…",
    "analyzers": [ { "id": "ast_taint", "version": "0.1.0", "artifact_hash": "sha256:…", "engine": "static", "status": "ok" } ]
  },
  "result": {
    "verdict": "PASS",
    "reasons": [ … ],
    "findings_digest": "sha256:…",     // JCS hash of the full, sorted findings list (stored alongside)
    "findings_summary": [ { "threat": "…", "severity": "…", "count": 1 } ]
  },
  "decision": { "kind": "automated" },  // or { "kind": "admin_review", "reviewer": "…", "decision": "approve", "scan_attestation_id": "…" }
  "issued_at": "2026-…Z"
}
// envelope
{ "payload": {…}, "attestation_id": "sha256(JCS(payload))", "key_id": "…", "signature": "ed25519 hex" }
```

- **Reproducibility digest:** `sha256(JCS({subject, pipeline, result}))` is identical across re-runs of the same input. This is the precise form of the "deterministic" claim. `issued_at` is the only field that may differ. Today `scannedAt` sits inside the signed record, which contradicts the "byte-identical" claim.
- The current browser verifier (`public/js/mcpsecure.js:776`) moves to v2. v1 records stay readable.

### 8.3 What gets logged (D1)

**Recommendation: sign and log every final decision**: automated PASS and FAIL, admin approve/reject of a REVIEW, and **revocations** (an approved server whose new version fails). Today only PASS is signed and logged; FAIL and REVIEW are unsigned, local-only rows.

The trust argument on slide 3 is that the marketplace cannot alter or backdate verdicts or hide a rug pull. That only holds if rejections and revocations are in the log too. REVIEW verdicts waiting for an admin are stored but not logged until decided.

### 8.4 Anchoring interface

```js
// src/mcpsecure/attest/anchor/index.js
anchor({ rootHash, treeSize })  → { network, txHash, blockNumber, blockTimestamp, rootHash, treeSize }
verifyReceipt(receipt)          → { ok, details }
```

- Implementations: `simulated` (*exists*, `service.js simulateAnchor`) and `sepolia` (Final 1).
- Anchor the **signed tree head** on a schedule (every N leaves or T minutes, both configured), not every leaf.
- Receipts are stored and served, so the browser can check a leaf → inclusion proof → STH root → on-chain transaction through a public RPC.

---

## 9. Marketplace integration

### 9.1 Submission lifecycle

```
DRAFT ─submit─▶ QUEUED ─▶ INGESTING ─▶ SCANNING ─▶ ┬─ PASS   ─▶ APPROVED  (listed, signed)
                                │           │       ├─ REVIEW ─▶ IN_REVIEW ─admin─▶ APPROVED | REJECTED (signed)
                                ▼           ▼       └─ FAIL   ─▶ REJECTED  (signed)
                          INGEST_FAILED  SCAN_FAILED   (retryable; never listed)
```

- **A server is listed only while it has an APPROVED version.** The catalog and install instructions pin that version's `commit_sha`.
- **Today the gate does not exist:**
  - `POST /api/servers` (`src/routes/api.js:93`) lists a server immediately;
  - the publish page calls `/scan-preview`, which discards tool source (`src/routes/mcpsecure.js:560`) and saves nothing;
  - Approve/Reject in the admin page only changes the DOM (`public/admin.html:181`).
- **Updates:** a new commit (pushed by the publisher or seen by the watcher) creates a new submission version. While it is scanned or reviewed, the previously approved pinned version stays listed with a notice (D5). If the new version is REJECTED, the approval is revoked and the listing is suspended. The revocation is stored as a decision record; signing and logging it is deferred with §8.3.
- **Admin review:**
  - users get a `role` (`publisher` / `admin`), and only admins can call decision endpoints;
  - a decision requires a note and is stored as a `review_decisions` row (signing it is deferred with §8);
  - the review card shows policy reasons, findings with code excerpts, and Model C's advisory.

### 9.2 API (new, versioned; existing `/api/mcs/*` read endpoints stay for the explorer pages)

| Method | Path | Who | Purpose |
|---|---|---|---|
| POST | `/api/v1/submissions` | publisher | `{source:{kind:"git",repo_url,ref} \| upload, listing:{…}, declared_tools:[…]}` → `202 {submission_id, job_id}` |
| GET | `/api/v1/submissions/:id` | owner, admin | state, versions, latest scan |
| GET | `/api/v1/jobs/:id/events` | owner, admin | SSE progress (§10) |
| GET | `/api/v1/review-queue` | admin | IN_REVIEW submissions with reasons |
| POST | `/api/v1/submissions/:id/decision` | admin | `{decision: approve\|reject, note}` → signed decision |
| POST | `/api/v1/verify` | anyone (rate-limited) | external, never onboarded (slide 6): `{repo_url, ref}` → job → attestation |
| GET | `/api/v1/attestations/:id`, `/api/v1/log/…`, `/api/v1/anchors` | public | verification |

---

## 10. Jobs and progress

- A scan can take minutes: Model B takes about 55 s for 700 functions on CPU (Apple M-series, 8 threads). Scans therefore run as jobs, never inside the HTTP request.
- `scan_jobs` is a database table worked by an in-process worker. Concurrency is configurable (default 1, because the models are CPU-bound), and jobs left `running` at restart are resumed. No Redis is needed at this scale.
- Progress events keep the existing SSE shape (`stage`, `status`, `ms`, detail fields; *exists*, `GET /api/mcs/scan/stream`): `ingest`, one per analyzer, `policy`, `triage`, `attest`, `log`, `anchor`. Durations go to the stream only, never into the signed record.

---

## 11. Storage

- **Move from sql.js to better-sqlite3.** sql.js keeps the whole database in memory and rewrites the entire file on every write (`src/db.js:100`). That will not survive concurrent jobs or a growing log. better-sqlite3 has a similar synchronous API, so `db.js` callers barely change. Postgres can wait for deployment (D6).
- New tables:
  - `submissions` and `submission_versions` (commit SHA, fingerprint, state);
  - `scan_jobs`;
  - `analyzer_results` (raw contract responses);
  - `findings` (one row per finding, indexed by threat and server);
  - `attestations` (v2 envelopes);
  - `review_decisions`.
- `users.role` added. `servers` gains `listing_status` and `approved_version_id`.
- Kept as is: `mcs_log_leaves`, `mcs_anchor_receipts`, `mcs_watcher_rows`.
- Migrations become numbered files run once each (`database/migrations/NNN_*.sql`). This replaces the try/catch `ALTER` loop.

---

## 12. MCP Secure server (Final 2: Muhammad), reserved here

A separate small Node process using `@modelcontextprotocol/sdk` over Streamable HTTP. Tools:

- `verify_mcp_server({repo_url, ref})`: calls `POST /api/v1/verify`, waits for the job, returns the signed attestation and a human-readable verdict;
- `lookup_attestation({content_fingerprint | attestation_id})`: returns the stored attestation and its inclusion proof.

It holds no keys and runs no analyzers. That is why the orchestrator must stay headless and callable (§5).

---

## 13. Evaluation CLI (Pre-Job Fair: Talha)

`node bin/mcs-scan.js <git-url | dir> [--ref main] [--json] [--batch list.txt]` runs stages 1–3 (optionally 4–5 with `--attest`). It uses exactly the production code, with no database or marketplace.

Uses:

- the evaluation and baseline comparisons on slide 8;
- regression sets (Model B's 46 wild servers, `test_mcp_new`);
- CI: exit code 0 = PASS, 1 = FAIL, 2 = REVIEW, 3 = error.

---

## 14. Repository layout (target)

The existing `ast_taint_analyzer/` and `model_b_service/` paths stay where they are, so teammates' branches keep merging cleanly.

```
server.js, src/routes/, public/, database/        marketplace (existing)
src/mcpsecure/
  ingest/        sources (git, upload, local), discover/ (python, typescript), bundle.js, fingerprint.js
  orchestrator/  pipeline.js, registry.js, client.js (contract HTTP client), jobs.js
  analyzers/     builtin/text_heuristic.js, builtin/code_heuristic.js   (fallbacks, same contract)
  policy/        engine.js, ruleset.json
  attest/        jcs.js, crypto.js, attestation.js, log.js, anchor/{simulated,sepolia}.js
  store/
contracts/       *.schema.json, threats.json, fixtures/ (golden bundles)
services/analyzer_kit/                              shared Python HTTP + contract helper
ast_taint_analyzer/   + service.py                  (Mustafa)
model_b_service/      + /v1 endpoints               (Talha)
model_a_service/, model_c_service/                  (Talha, later)
demo_servers/    weather-tools/, db-helper/, shell-runner/, …   real code, ingested through `local`
bin/mcs-scan.js, scripts/conformance.js
mcp_secure_server/                                  (Final 2)
```

---

## 15. Changes to the POC

Grouped by what they unblock. File references are to `feat/model-b-v8`.

**Gate and lifecycle**

1. Replace `/scan-preview` and the unscanned `POST /api/servers` with submissions (§9).
2. Persist admin decisions and add `users.role`. Today `/admin` is reachable by any logged-in user.
3. `/verify-external` (`src/routes/mcpsecure.js:416`) scans a hard-coded "acme" candidate. Route it through real ingestion.

**Correctness**

4. The fingerprint must include code (§4.6, `engine.js:508`).
5. Use a real commit SHA instead of `simulateCommitSha()`.
6. No PASS without coverage (§1, §7). Non-Python servers currently get a markdown regex and can PASS, and an unset `MODEL_B_URL` silently uses the simulated heuristic.
7. AST line numbers must be per file. Corroboration must match by file and function span (§6.2).
8. *(Deferred with §8)* JCS canonical JSON for hashing and signing (§8.1).
9. *(Deferred with §8)* Move `scannedAt` out of the reproducible part (§8.2).
10. Rename PMA to `preference_manipulation` (§6.3).

**Robustness**

11. The AST analyzer becomes a service. `execFileSync` (`astTaint.js:58`) blocks the Node event loop for up to 20 s.
12. Move from sql.js to better-sqlite3, with numbered migrations (§11).
13. Read the session secret and config from the environment (`server.js`).
14. Add Node tests (`node:test`): ingestion (safety cases included), policy regression, attestation round trip, contract client. There are none today.

**Data and demo**

15. Demo servers become real code in `demo_servers/` and go through the same ingestion path. Their source is now held as strings in `seed.js`.
16. Seeded catalog servers point at fake `github.com/example/*` URLs, so they cannot be scanned. Mark them `legacy_unscanned`, or replace them with real MCP repos (Model B's 46 wild servers are a ready list).
17. Keep the watcher's `simulate-update` buttons, but behind a `DEMO_MODE` flag. The real watcher polls `git ls-remote` (Final 1).
18. Model weights (23 MB adapter + tokenizer) are committed directly to git. Move them to a GitHub Release or a Hugging Face repo, pinned by the hash `model_b.py` already computes. Low priority.

---

## 16. Decisions for the team

| # | Decision | Decided |
|---|---|---|
| D1 | Sign and log FAIL, admin decisions and revocations, or only PASS (current)? | **Deferred** to the blockchain phase. Current behaviour stays meanwhile. The proposal is all final decisions (§8.3). |
| D2 | Can Model C change a verdict? | **No, advisory only.** ✅ Keeps the verdict offline and deterministic; the admin makes the final call. |
| D3 | Servers the code analyzers cannot cover (Go/Rust, remote-only)? | **REVIEW with an "insufficient coverage" reason** ✅, never PASS. Text-only analysis of remote servers comes later. |
| D4 | Run the server in a sandbox to call `tools/list` (catches runtime-built descriptions)? | **Not now.** ✅ Static discovery plus the declared-vs-discovered check. Revisit after Final 1; it would need a no-network container. |
| D5 | An update to an approved server lands in REVIEW: keep the old version listed? | **Yes, pinned to the approved commit, with a notice.** ✅ Suspend only on REJECTED. |
| D6 | Database | **better-sqlite3 now** ✅, Postgres at deployment if needed. |
| D7 | Where model weights live | **GitHub Release, hash-pinned** ✅ (the service downloads on first start and checks the model hash). |
| D8 | Endpoint names: slide 7 shows `/api/predict/text` and `/api/predict/code` | **`/v1/analyze` on every service, plus the slide paths as aliases** ✅ (`/api/predict/code` on Model B, `/api/predict/text` on Model A). |

---

## 17. Phased plan (mapped to slide 9 milestones)

| Phase | Milestone | Deliverables |
|---|---|---|
| 0 | now | Merge PR #2 into `main`. Team agrees this spec and the D1–D8 decisions. |
| 1 | **Mid 1** (command injection + AST) | `contracts/` + conformance suite; **ingestion** (git/upload/local, Python+TS discovery, bundle, fingerprint); AST and Model B behind the contract; orchestrator + jobs + registry + built-in fallbacks; policy-v4 that reproduces v3; submissions + persisted admin review; demo servers as real code; better-sqlite3; POC fixes 1–17 except 8–9 (deferred with §8) |
| 2 | **Final 1** (full threat detection) | Model A and Model C services plugged in through the registry (Talha); policy engine generalised (Mustafa); real watcher (Muhammad). **Blockchain work (§8: attestation v2, JCS, D1, Sepolia, receipt verification) is scheduled when the team takes it up.** |
| 3 | **Pre-Job Fair** (end-to-end) | Evaluation CLI runs and baselines (Talha); integrated verdict and UI (Mustafa); everything live (Muhammad) |
| 4 | **Final 2** (MCP server + deployment) | MCP Secure server (Muhammad); hosted model endpoints (Talha); verification pipeline (Mustafa); `docker compose` deployment of the marketplace and all services |

Phase 1 is ordered so that each step leaves the app working:

1. Contracts.
2. Ingestion behind the current engine.
3. AST and Model B as contract services.
4. Orchestrator replacing `simulateScan`.
5. Policy-v4 with the regression gate.
6. Submissions and admin review.
7. Database move.

---

## Appendix A: Baseline measured on `feat/model-b-v8` (2026-10-12)

The real AST analyzer (v0.1.0, config `6352f087…`) and the real Model B service (hash `3276ec25…`, matching `ruleset.json`) ran on macOS arm64, Python 3.13, CPU. Model A is still the heuristic. These six verdicts are the **policy-v4 regression gate** (§7).

| Server | Bait & switch | Verdict | AST | Model B (effective) | Model A (heuristic) |
|---|---|---|---|---|---|
| weather-tools | no | PASS | 0 | 0 | 0 |
| weather-tools | yes | FAIL | 1.0 | 0.999 (corroborated) | 1.0 |
| db-helper | no | REVIEW | 0 | 0.55 (see below) | 0.6 |
| db-helper | yes | FAIL | 1.0 | 0.999 | 1.0 |
| shell-runner | no | FAIL | 1.0 | 1.0 (corroborated ×2) | 0.8 |
| shell-runner | yes | FAIL | 1.0 | 1.0 | 1.0 |

Observations:

- **db-helper.** Model B scores the parameterised `query_db()` as `sql_injection` 0.77, which is a false positive. The corroboration rule caps it at 0.55 (REVIEW), so the REVIEW verdict is *not* "from Model A alone", as the merge commit says. No AST corroboration is possible for SQL injection today, so this class can only ever reach REVIEW.
- **Wasted clones.** On every scan Model B tries to clone the seeded `github.com/demo/*` URLs, which do not exist. Ingestion (§4) removes this.
- **Evidence line numbers.** They are relative to per-tool temp files (`tools/0_query_db.py:1`), not the real repository (§4.5).

---

## Appendix B: Phase 1 implementation status (2026-10-12)

**Built**

- **Ingestion (§4):**
  - `src/mcpsecure/ingest/`: git (`ls-remote` pin, hardened shallow fetch, GitHub `/tree/<ref>/<subdir>` links), file uploads, and local/demo sources;
  - the shared file filter with limits and symlink skipping;
  - Python and TypeScript tool discovery, including the low-level SDK patterns;
  - the bundle (`contracts/analysis-bundle.schema.json`) and a fingerprint that covers the code.
- **Analyzer contract (§6):**
  - JSON Schemas and `contracts/threats.json`;
  - `services/analyzer_kit/`;
  - `ast_taint_analyzer/service.py` (:8701) and the Model B `/v1` endpoints, with the `/api/predict/code` alias (:8765);
  - both pass `npm run conformance`.
- **Orchestrator (§5):**
  - registry `config/analyzers.json`;
  - built-in Model A stand-in and declared-vs-discovered check;
  - fail-closed client;
  - local services are started by `npm start`.
- **Policy-v4 (§7):**
  - rule types in `src/mcpsecure/policy/engine.js`;
  - it reproduces all six Appendix A verdicts (`test/pipeline.test.js`).
- **Gate (§9):**
  - `/api/v1/submissions`, SSE progress, `/api/v1/review-queue` and admin decisions with a required note;
  - listing states follow D5;
  - `POST /api/servers` returns 410;
  - publishers can no longer self-set `security_status`.
- **Storage (§11):** better-sqlite3 (WAL) with tracked migrations (`database/migrations.js`).
- **Demo servers (§15.15):** `demo_servers/` holds real Python and TypeScript servers plus `_bait/` rug-pull overlays. The watcher's docs-only and bait-and-switch buttons re-ingest for real.
- **CLI (§13):** `bin/mcs-scan.js`.
- **Tests:** Node `node:test` (ingestion safety, policy, listing, regression gate, HTTP-level API) and `ast_taint_analyzer/tests/test_service.py`.

**Differences from the text above**

- **Ports:** Model B stays on 8765, its existing port, not 8702.
- **No separate `scan_jobs` table (§10):** the `submissions` row is the job. A newer submission of the same server marks older queued or in-review ones `superseded`.
- **Analyzer pins:** `ruleset.json` pins the Model B artifact hash (`analyzerPins`), and rule `unpinned_analyzer_version` refuses PASS for an unreleased model. `release.py` updates the pin. Per-scan hashes are recorded from `/v1/health`.
- **`demo` source kind:** the publish and verify forms accept `demo:<name>`, which maps only to the bundled `demo_servers/`. Publishers can never submit arbitrary local paths.
- **No Model B fallback:** a missing Model B is reported as `unavailable` and blocks PASS. Model A keeps a labelled heuristic stand-in until the trained model is served.
- **Storage of results:** the full scan record (contract results, policy reasons, ingestion summary) is stored in `mcs_scan_records.record_json`.

**Not done yet**

- **Deferred with §8:** fixes 8–9, signing and logging of admin decisions, and Sepolia.
- **Watcher polling:** the real watcher (polling `git ls-remote`) is Final 1.
- **Archive uploads:** `.zip`/`.tar.gz` uploads are not supported; uploads are a JSON file list for now.
- **Weights (fix 18):** the model weights are still committed in git.
- **Legacy catalog (fix 16):** the seeded catalog rows keep fake URLs. They stay visible as `legacy`, and scanning them returns a 422 "no scannable source".

---

## Appendix C: Testing (2026-10-12)

Full results are in `spec/TEST_REPORT.md`. These changes came out of testing:

| Found by | Problem | Change |
|---|---|---|
| adversarial suite s04 | runtime code imported from `examples/` was never scanned | deferred directories + import reachability (§4.3) |
| adversarial suite s06 | a committed `dist/` entrypoint differing from `src/` was never scanned | package entrypoints admitted (§4.3) |
| adversarial suite s05 | padding a file past 400 KB removed it from analysis | `coverage.skipped_code` + rule `source_not_fully_analysed` |
| adversarial suite s03 | a description read from a file at runtime was never checked | `coverage.unresolved_descriptions` + rule `runtime_descriptions` |
| adversarial suite x04 | zero-width/bidi/tag characters hid instructions from reviewers | hidden-character check in `ingest_checks` |
| adversarial suite t04 | Model B dropped functions under 3 lines, so clean TS servers lost coverage, and one-line handlers were never scored | contract path scores 2+ line functions and every tool handler; coverage = a code analyzer ran |
| security review | any https host accepted as a git source (SSRF); refs starting with `-` reached git | host allowlist, ref validation, `--` |
| failure-mode tests | analyzer responses were trusted unvalidated | responses validated against the contract schema; invalid → `error` |
| unit test | a Python import regex swallowed the next import line | names span lines only inside parentheses |
