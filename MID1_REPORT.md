# MCP Secure — Mid 1 report

**State as of 15 Oct 2026** (`main` @ the commit that adds this file). Scope of this iteration: the
**code** path: ingestion, Model B, the AST (Python) and TS/JS taint analyzers, the policy, and the
marketplace around them. Model A (tool-description text) is **out of scope** for this iteration and is switched off
(`MCS_ENABLE_MODEL_A=1` brings back its regex stand-in).

Every number below comes from a file in this repository or the training outputs, named next to it.

---

## 0. Headline numbers

| What | Result | Source |
|---|---|---|
| Known-vulnerable MCP releases **blocked from auto-listing** (REVIEW or FAIL) | **62 / 66 (94%)** | `eval/results/run7gpu.md` |
| Known-vulnerable MCP releases **auto-rejected** (FAIL) | **25 / 66 (38%)** (v5 at the start of the review: 12 / 66) | same |
| TS/JS vulnerable releases auto-rejected | **11 / 37** (v5: 0 / 37) | same |
| Popular benign MCP servers **wrongly rejected** | **0 / 23** | same |
| Popular benign servers sent to REVIEW (human load) | 15 / 23 (65%) | same |
| Code-level attacks that **bypassed** detection (attack success rate) | **0 / 19 (0%)** | `eval/adversarial/` |
| Live GitHub testbed, code cases correct | **27 / 27** | §8.4 |
| Model B, cross-validated macro PR-AUC (6 classes) | **0.773 ± 0.010** | training run `model-b-v8` |
| Model B on unseen real MCP servers (`test_mcp_new`) | precision **86%**, recall **52%** at fail; 72% / 78% at review | same |
| AST analyzer fixture benchmark | **36 / 36** (precision 1.00, recall 1.00) | `ast_taint_analyzer/scripts/eval_fixtures.py` |
| Test suites | Node 65/65 · AST pytest 341/341 · browser 12/12 (+2 live) | `npm test`, `npm run test:e2e` |
| Scan time per server (clone + all analyzers, Kaggle T4) | median **3.6 s**, p95 26.9 s, max 135 s | `run7gpu.md` |

---

## 1. How to run it

Requirements: Node.js 20+, Python 3.9+, git, internet (testbed scans and the watcher go to GitHub).

```bash
git clone https://github.com/Talha-Qamar/mcp-marketplace.git
cd mcp-marketplace
npm install
npm run seed                      # database/marketplace.db: catalog, demo users, clients

# Model B, one time (~1 GB venv; first start downloads microsoft/unixcoder-base, ~500 MB)
cd model_b_service
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
(cd js && npm install)
cd ..

npm start                         # http://localhost:3000 — also starts AST (:8701) and Model B (:8765)
```

Accounts (password `password123`): `alice_dev@example.com` (publisher), `dave_sec@example.com` (admin).
Without the Model B venv the app runs, but the policy refuses to PASS anything (fail-closed).

| Command | Purpose |
|---|---|
| `npm test` | Node tests + the AST analyzer's pytest suite |
| `npx playwright install chromium` then `npm run test:e2e` | Browser end-to-end tests (throwaway DB) |
| `E2E_LIVE_TESTBED=1 npx playwright test tests/e2e/live_testbed.spec.js` | Live GitHub testbed + rug-pull flow (pushes to the testbed repo) |
| `npm run eval:adversarial` | 31 attack / evasion / benign cases with expected verdicts |
| `npm run scan -- <git-url \| demo:<name> \| dir> [--json]` | Headless scan; exit 0 PASS, 1 FAIL, 2 REVIEW, 3 error |
| `node scripts/testbed.js rugpull \| reset \| status` | Live rug pull on the testbed's `watcher-demo` branch |
| `npm run eval` → `npm run eval:report` | Full real-world evaluation (hours on CPU; use Kaggle, §11) |
| `node eval/replay.js <run> [--md]` | Re-decide a stored run under several rulesets in seconds |

**Demo flow:** `/scan` (bundled demos: Weather Tools and DB Helper PASS, Docs Helper REVIEW, Shell Runner
FAIL; every FAIL/REVIEW shows **Why this verdict** with the exact code lines) → `/publish` as alice, pick a case
from **Live GitHub testbed** → `/admin` as dave (review queue, note required) → publish `watcher-demo`,
run `node scripts/testbed.js rugpull`, press **Poll Now** on `/watcher` (listing suspended) →
`/attestations` (verify a PASS) → `/verifier` (external scan, never listed). Reset with
`node scripts/testbed.js reset`.

---

## 2. Mid 1 deliverables (spec §17, phase 1) and status

| Deliverable | Status |
|---|---|
| Analyzer contract (`contracts/`) + conformance suite | Done |
| Ingestion: git (pinned commit), uploads (JSON file list), local/demo; Python + TS tool discovery; bundle; code-covering fingerprint | Done (zip/tar uploads not yet) |
| AST and Model B behind the contract | Done |
| Orchestrator, registry, built-in fallbacks, fail-closed | Done |
| Policy that reproduces the earlier verdicts (regression gate) | Done; now policy-v7 (§6) |
| Submissions gate + persisted admin review | Done |
| Demo servers as real code; better-sqlite3 + migrations | Done |
| POC fixes 1–17 (8–9 deferred with blockchain §8) | Done, incl. fix 17 (`DEMO_MODE`) |
| **Added in the Mid 1 review:** TS/JS taint analyzer, AST SSRF/SQL/getattr, policy-v6/v7, live GitHub testbed, real watcher poll, evaluation on Kaggle with replay | Done |

Not in this iteration: Model A (switched off, out of scope), blockchain anchoring
(simulated; signatures and the Merkle log are real), Model C (not built), scheduled watcher (manual
Poll Now), the verifier's "AI Tool Calling" tab (mock of the Final 2 MCP server). The 59 seeded catalog
servers are browsable `legacy` rows with placeholder URLs and cannot be scanned.

---

## 3. How the pipeline decides

```
submit (git URL @ ref | testbed branch | demo | file list)
  → INGEST   git ls-remote → pinned commit → shallow fetch (no code is ever executed)
             file selection, tool discovery (Python ast / TypeScript compiler), fingerprint
  → ANALYZE  in parallel, one contract: ast_taint (Python) · ts_taint (TS/JS) · model_b
             · ingest_checks (hidden characters, declared vs found tools)
  → POLICY   deterministic rules (ruleset.json, policy-v7)
  → OUTCOME  PASS → listed + signed attestation + Merkle log entry
             REVIEW → admin queue (hidden until approved)
             FAIL → rejected (or suspended if it was listed: rug pull)
  → WATCHER  Poll Now: new commit on a listed repo → re-scan through the same gate
```

---

## 4. Model B — the code classifier

### 4.1 Task
Function-level, multi-label classifier over MCP-server source (Python, TypeScript, JavaScript).
Classes: `cmdi` command injection (CWE-78), `path` path traversal (CWE-22), `ssrf` (CWE-918), `codei`
code injection (CWE-94), `sqli` SQL injection (CWE-89), `deser` unsafe deserialization (CWE-502).
It is an end-to-end scanner: raw code in, per-class scores out. Data-flow proof is the taint analyzers'
job, combined at the policy layer (§6).

### 4.2 Data (Kaggle dataset `muhammadtalhaqamar/model-b-v8-data`, v8.2)

**Sources (real, pre-labelled):** vulnerable/fixed function pairs from GitHub Security Advisory / OSV
fix commits (the function before the fix = vulnerable, after = fixed twin), SVEN, GHSA MCP CVEs, and a
hand-curated MCP set. Every pair was **reviewed by hand**; a pair was kept only when the vulnerable
function itself contains the flaw (pairs where the fix was elsewhere, incidental, or uncertain were
dropped; wrong-class pairs relabelled). Safe code: ordinary functions from real MCP-server repositories,
risky APIs used with literal arguments only, and the fixed twins. No hand-written malicious code.

| split | functions | vulnerable | safe | repos |
|---|---|---|---|---|
| train_pool | 29,058 | 1,213 | 27,845 | 694 |
| synthetic_train (train only) | 1,280 | 640 (cmdi) | 640 | – |
| test_fresh_cmdi | 21 | 12 | 9 | 6 |
| test_v6 | 45 | 23 | 22 | 19 |
| test_mcp_new (real MCP servers) | 161 | 81 | 80 | 25 |
| wild_eval (unlabelled MCP code) | 23,010 | – | – | 46 |

Vulnerable functions per class (train_pool):

| class | vulnerable | with fixed twin | repos | Python | TS/JS |
|---|---|---|---|---|---|
| cmdi | 268 | 257 | 118 | 94 | 174 |
| path | 443 | 436 | 230 | 273 | 170 |
| ssrf | 145 | 142 | 79 | 76 | 69 |
| codei | 122 | 119 | 69 | 78 | 44 |
| sqli | 128 | 120 | 51 | 66 | 62 |
| deser | 107 | 103 | 61 | 107 | 0 |

Safe functions in train_pool: 24,636 ordinary · 2,019 literal-only risky API · 1,124 fixed twins
(hard negatives) · 66 curated. At most 12 pairs per repository per class.

**Checks passed:** hand-review verdicts present, repository-disjoint splits, no exact or near duplicates
between test and train, no contradictory labels, every class in every fold. Three repository-grouped
folds (~9,690 functions each, every class balanced across folds).

### 4.3 Training (Kaggle notebook `muhammadtalhaqamar/model-b-v8`, NVIDIA T4)

**Model selection (sweep, validation fold 0, repo-grouped):**

| config | backbone | adapter | trainable params | macro PR-AUC | any-vuln PR-AUC | ordinary flagged |
|---|---|---|---|---|---|---|
| gcb_r32 | GraphCodeBERT | LoRA r32 q/k/v/dense | 5.9 M | 0.545 | 0.643 | 0.40% |
| gcb_r32_ord2 | GraphCodeBERT | LoRA r32, 2× ordinary negatives | 5.9 M | 0.540 | 0.631 | 0.20% |
| gcb_r64 | GraphCodeBERT | LoRA r64 | 11.2 M | 0.552 | 0.653 | 0.67% |
| gcb_r16_qv | GraphCodeBERT | LoRA r16 q/v | 1.2 M | 0.514 | 0.611 | 0.33% |
| gcb_r32_nosyn | GraphCodeBERT | LoRA r32, no synthetic | 5.9 M | 0.565 | 0.653 | 0.27% |
| **unix_r32 (winner)** | **UniXcoder** | **LoRA r32 q/k/v/dense** | **5.9 M** | **0.586** | **0.676** | 0.67% |
| gcb_full | GraphCodeBERT | full fine-tune | 124.7 M | 0.535 | 0.632 | 0.13% |

**Final configuration (`unix_r32`):** `microsoft/unixcoder-base` (pinned revision) + LoRA r = 32,
α = 64 on query/key/value/dense, merged at inference · multi-label sigmoid head, BCE with per-class
`pos_weight` · lr 2e-4, weight decay 0.01, warmup 6%, batch 8, fp16, seed 42 · up to 6 epochs, early
stopping (patience 2) on macro PR-AUC · input = 510-token windows, stride 256 (up to 6 per function in
training, 64 at inference); function score = max over windows · training mix per fold: all vulnerable +
all fixed twins + ordinary code 1:1 with vulnerable + literal-only code 1:1 + the 640 synthetic pairs.

**Protocol:** 3-fold repository-grouped cross-validation (best epochs 3 / 6 / 5, 35–42 min each) →
out-of-fold scores pick the thresholds → final model trained on the whole pool for the CV-average
epoch count (5 epochs, 6,109 rows / 7,933 windows, 35.8 min) → evaluated **once** on the three test
sets and the wild set. Whole run ≈ 2 h 50 min on a T4.

**Thresholds** (raw sigmoid, per class, from out-of-fold scores; *fail* = best F2 with precision ≥ 70%
and ≤ 0.5% of ordinary code flagged; *review* = lowest threshold with precision ≥ 50%). Raw scores are
mapped piecewise-linearly so review → 0.40 and fail → 0.75 on the marketplace scale.

| | cmdi | path | ssrf | codei | sqli | deser |
|---|---|---|---|---|---|---|
| fail (raw) | 0.15 | 0.75 | 0.97 | 0.33 | 0.61 | 0.73 |
| review (raw) | 0.03 | 0.32 | 0.39 | 0.02 | 0.03 | 0.06 |

**Release:** `model_b_service/model_b_v8/` (23 MB adapter + tokenizer), model hash
`sha256:3276ec25…c7289`, pinned in `ruleset.json` (a different model cannot PASS anything). CPU vs
Kaggle parity: worst |difference| 0.0001 over 227 test functions.

### 4.4 Results

**Cross-validation (out-of-fold):** macro PR-AUC **0.773 ± 0.010**, any-vulnerability PR-AUC 0.784,
recall 76.9%, precision 70.4%, ordinary code flagged 0.69%, literal-only risky code flagged 1.34%.

| class | PR-AUC | fail: precision / recall | review: precision / recall | vuln scored above its fix | fix still reaches review |
|---|---|---|---|---|---|
| cmdi | 0.88 | 76% / 93% | 61% / 96% | 96% | 32% |
| path | 0.69 | 70% / 58% | 52% / 85% | 81% | 60% |
| ssrf | 0.63 | 74% / 17% | 50% / 74% | 76% | 43% |
| codei | 0.83 | 71% / 86% | 57% / 92% | 87% | 40% |
| sqli | 0.78 | 71% / 69% | 51% / 89% | 89% | 59% |
| deser | 0.82 | 71% / 88% | 50% / 99% | 89% | 64% |

**Held-out test sets (final model, evaluated once):**

| set | at fail: precision / recall | at review: precision / recall |
|---|---|---|
| test_mcp_new (real MCP servers, 25 repos) | 86% / 52% | 72% / 78% |
| test_v6 | 92% / 100% | 85% / 100% |
| test_fresh_cmdi | 100% / 92% | 100% / 92% |

test_mcp_new per class (PR-AUC, recall at review): cmdi 1.00 / 100% (n=4) · path 0.54 / 68% (n=25) ·
ssrf 0.54 / 61% (n=18) · codei 0.65 / 60% (n=5) · sqli 0.98 / 97% (n=29).

**Wild MCP code (23,010 unlabelled functions, 46 servers):** 9.3% of functions reach fail, 21.3% reach
review; ordinary functions without risky APIs 0.57% / 2.7%. Used alone as "server score = highest
function", Model B would fail 41 of 46 real servers — which is why the policy never lets it fail a
server alone (§6).

### 4.5 Known weaknesses
Path traversal and SSRF are the weakest classes; the model often still scores the *fixed* function
high (see "fix still reaches review"); small per-class real-MCP test sets (cmdi 4, codei 5, deser 0);
one reviewer labelled the pairs. Improvement plan: §10.

---

## 5. Taint analyzers (static data-flow proof)

### 5.1 AST taint analyzer — Python (`ast_taint_analyzer/`, service on :8701)
Parses Python with the standard-library `ast` (never executes), treats every MCP tool parameter as
attacker-controlled, propagates taint through assignments, f-strings, concatenation, string methods,
containers and wrappers, and reports when it reaches a sink.

| Category | Sinks | Condition | Threat |
|---|---|---|---|
| shell | `os.system`, `os.popen`, `os.exec*`, `subprocess.*` | subprocess only with `shell=True` | command_injection |
| exec / dynamic | `eval`, `exec`, `compile`, `getattr`, `__import__`, `importlib` | – | code_injection |
| file | `open`, `pathlib.Path` | – | path_traversal |
| deserialize | `pickle.load(s)`, `marshal.loads`, `yaml.load` | yaml only without SafeLoader | unsafe_deserialization |
| **network (new)** | `requests.*`, `httpx.*`, `urllib.request.*`, `aiohttp.request` | URL **starts** with tool input | ssrf |
| **sql (new)** | `.execute`, `.executemany`, `.executescript`, `.raw`, `sqlalchemy.text` | SQL **built** from tool input (f-string, `+`, `%`, `.format`; placeholder lists excluded) | sql_injection |

Also new: `getattr(module, "<constant>")` resolves to the real sink (`"sys" + "tem"` → `os.system`).
Severity: shell/exec within 2 hops = high (a hard FAIL), others medium, sanitized (`shlex.quote` …) low.
**Results:** fixture benchmark 36/36 (20 vulnerable detected, 10 safe clean, 6 edge cases handled),
341 pytest tests pass. Limit: no inter-procedural flow (plan E3).

### 5.2 TS/JS taint analyzer (`src/mcpsecure/analyzers/builtin/ts_taint.js`, new)
TypeScript compiler API, static. Sources: tool handler parameters and `CallToolRequestSchema`
dispatchers. Follows calls into the server's own functions across files (same file, relative imports,
unique names; up to 4 deep). Sinks: `child_process` exec / shell spawn, `eval` / `new Function` /
`vm`, `fs.*`, `fetch` / `axios` / `got` / `http` (URL must start with tool input), SQL methods (SQL must
be built from tool input). Sanitizers and guards (`validateServerUrl(url)`, `if (!isPathAllowed(p))`)
make a flow low; `.map(() => '?')` placeholder lists are clean. 20 s budget per bundle (status
`partial` if exceeded). 7 unit tests. Example it proves: `git_add(args)` → `addGitFiles(input)` →
`exec(command)` in `cyanheads/git-mcp-server` v2.1.4 (the published advisory).

---

## 6. Policy-v7 (`src/mcpsecure/ruleset.json`, engine `src/mcpsecure/policy/engine.js`)

Rules apply in order; the strictest verdict wins.

| # | Rule | Effect |
|---|---|---|
| 1 | required analyzer did not run · model not the pinned version · no code analyzed · no tools found · code files skipped · descriptions built at runtime | REVIEW (never PASS without coverage) |
| 2 | `ast_high_hard_fail`: Python AST high finding | FAIL |
| 3 | `model_b_requires_corroboration`: a Model B finding keeps its score only if a taint analyzer (Python or TS) reports a medium/high flow of the same threat in an overlapping function, **or** it lies inside a tool handler with score ≥ 0.85 (not for SQL injection: database tools query by design). Otherwise ≥ 0.75 → 0.55, 0.40–0.75 → 0.25 | caps |
| 4 | `ts_taint_requires_model_b`: a TS taint flow keeps its score only if Model B flags the same threat there | caps |
| 5 | thresholds on the highest effective score | ≥ 0.75 FAIL · ≥ 0.40 REVIEW · else PASS |

Principle: **an automatic FAIL needs two independent signals** (the model says "this code looks
vulnerable" and the static analyzer proves tool input reaches it), except the Python AST's direct
shell/exec flows, which are precise enough to fail alone.

---

## 7. Evaluation method (real-world)

* **Vulnerable set** (`eval/corpus.json`, built by `eval/build_corpus.py` from the GitHub Advisory
  Database): every npm/pip MCP package advisory with CWE 77/78/88/94/95/22/59/73/89/918/502 → the last
  vulnerable release tag (66 releases, 51 repositories) and the first fixed tag (55 pairs). Lines the
  fix changed are cached in `eval/fix_lines.json` (localization).
* **Benign set** (`eval/benign.json`): 27 popular MCP servers at HEAD (23 regular, 4 that execute
  commands by design: kubernetes, blender, desktop-commander, ios-simulator).
* **Runs** on Kaggle T4 (`muhammadtalhaqamar/mcp-secure-eval-gpu`) with the production pipeline;
  every scan stores a replay record so rule changes are compared on identical analyzer output
  (`eval/replay.js`). Model B on CUDA (`MODEL_B_DEVICE=cuda`) for speed; CPU is the production default.
* **Metrics:** *caught* = not PASS (not auto-listed) · *auto-rejected* = FAIL · *threat match* = a
  finding of the advisory's class · *localized* = a finding inside the code the fix changed.

---

## 8. Results

### 8.1 Progression on the same 148 scans

| | v5 (start of review) | v6 | **v7 (current)** |
|---|---|---|---|
| Vulnerable releases FAIL | 12 / 66 (18%) | 21 / 66 (32%) | **25 / 66 (38%)** |
| … Python / TS-JS / mixed | 8/19 · 0/37 · 4/10 | 10/19 · 7/37 · 4/10 | **10/19 · 11/37 · 4/10** |
| Vulnerable not PASS | 62 / 66 | 62 / 66 | 62 / 66 |
| Patched releases FAIL | 11 / 55 | 14 / 55 | 16 / 55 |
| Verdict improves after the fix | 2 / 55 | 4 / 55 | 6 / 55 |
| Benign FAIL / REVIEW / PASS | 0 / 15 / 8 | 0 / 15 / 8 | **0 / 15 / 8** |
| Exec-by-design FAIL / REVIEW / PASS | 1 / 3 / 0 | 1 / 3 / 0 | 1 / 3 / 0 |

### 8.2 v7 in detail (`eval/results/run7gpu.md`)

| Threat | Releases | Not PASS | FAIL | Threat match |
|---|---|---|---|---|
| command_injection | 22 | 100% | 50% | 100% |
| path_traversal | 23 | 96% | 39% | 91% |
| ssrf | 24 | 92% | 17% | 92% |
| code_injection | 4 | 75% | 50% | 50% |
| sql_injection | 1 | 100% | 100% | 100% |

Localized, threat-matched finding found by: Model B 41/55 · ts_taint 10/55 · ast_taint 4/55.
Vulnerable → fixed: REVIEW→REVIEW 29, FAIL→FAIL 15, FAIL→REVIEW 5, PASS→PASS 3, FAIL→PASS 1,
PASS→REVIEW 1, REVIEW→FAIL 1. 0 ingestion errors.

**Leakage check.** 4 of the 51 vulnerable repositories and 5 of the benign repositories also appear in
Model B's training pool. Excluding them: vulnerable FAIL 23/62 (37%), not PASS 58/62 (94%), patched
FAIL 15/53, benign 0 FAIL / 12 REVIEW / 6 PASS — the results are not inflated by the overlap.

### 8.3 Adversarial suite and attack success rate (`eval/adversarial/`, 31 cases)

| Group | Attacks | Bypassed (PASS) — attack success | Auto-rejected | Notes |
|---|---|---|---|---|
| code (direct injections, all classes) | 10 | **0 (0%)** | 10 | |
| evasion (aliased import, getattr, helper, backdoor) | 3 | **0 (0%)** | 3 | getattr gap closed in this review |
| hiding (examples/, committed dist/, padding) | 3 | **0 (0%)** | 2 | padding → REVIEW (unanalysed source) |
| coverage (Go-only, no tools, runtime description) | 3 | **0 (0%)** | 0 | REVIEW by design |
| **Code-level total** | **19** | **0 / 19 (0%)** | 15 | |
| text (tool poisoning, Model A — out of scope) | 6 | 4 (67%) | 0 | regex stand-in |
| benign controls | 6 | – | – | 5 correct; 1 stand-in false positive (`system:`) |

### 8.4 Live GitHub testbed (`Talha-Qamar/mcp-secure-testbed`, one branch per case)

All 27 code cases correct when scanned live from GitHub (17/27 under v5): command injection (Python,
TS, aliased, getattr, helper), code injection, deserialization, path traversal (Python, TS), SSRF, SQL
injection, backdoor, hidden `dist/` and `examples/` code, rug pulls, runtime descriptions, Go-only, and
6 clean controls. The 5 text cases need Model A (out of scope).

---

## 9. What limits the numbers (measured)

Re-deciding the 148 scans with an *ideal* Model B shows where the remaining gaps are:

| Scenario | Vulnerable FAIL | Patched FAIL | Benign REVIEW |
|---|---|---|---|
| Now (v7) | 21/55* | 16/55 | 15/23 |
| Model B fires only on the code the security fix changed | 22/55 | – | – |
| Model B never fires on patched code | – | 0/55 (PASS 4 → 32) | – |
| Model B never fires on safe code | – | – | 11/23 |

\*releases with a fix diff. So: **auto-reject rate is limited by the taint analyzers** (proof of flow),
not by Model B; **telling vulnerable from patched code and the review load are limited by Model B**.

---

## 10. Next steps

**Model B (after Mid 1, ~3–4 days, mostly human review):** remove the 9 overlapping repositories from
training; add reviewed vulnerable/fixed pairs from advisory fix commits outside the evaluation repos
(path, SSRF first); add a pairwise loss (vulnerable must outscore its fix); reviewed hard negatives from
v8.2's false alarms on real MCP code; per-class thresholds on MCP-only scores; retrain on a T4; accept
only if patched FAIL drops, vulnerable FAIL does not, and benign FAIL stays 0. Expected (not
guaranteed): patched FAIL 16 → ~8–10, fix-improves 6 → ~15–20, benign REVIEW 15 → ~13.

**Taint analyzers:** Python inter-procedural flow (E3); TS type-aware call resolution; re-enable the
reachability rule after fixing its anchoring (spec Appendix D).

**Platform (Final 1/2):** Model A service, Model C triage, scheduled watcher, zip/tar uploads, Sepolia
anchoring, deployment.

---

## 11. Reproduce the numbers

```bash
npm test                                   # Node + AST suites
(cd ast_taint_analyzer && PYTHONPATH=src python3 scripts/eval_fixtures.py)   # AST benchmark 36/36
npm run eval:adversarial                   # 31 cases
node eval/run_eval.js --set all --out runX # real-world evaluation (Kaggle T4: ~25 min; CPU: hours)
node eval/report.js runX                   # eval/results/runX.md
node eval/replay.js runX --md              # compare rule variants on the same scans
```

Model B training: Kaggle notebook `muhammadtalhaqamar/model-b-v8` (dataset
`muhammadtalhaqamar/model-b-v8-data`); release with `python model_b_service/release.py <output-dir>`,
parity with `python model_b_service/parity_check.py`.

**Further reading:** `spec/PIPELINE_SPEC.md` (design; Appendices D–F cover this review),
`model_b_service/MODEL_CARD.md`, `ast_taint_analyzer/README.md`, `README-POC.md`.
