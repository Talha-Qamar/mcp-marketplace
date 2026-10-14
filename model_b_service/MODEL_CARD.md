# Model B v8.2 — model card

Function-level classifier for code vulnerabilities in MCP-server source. Part 3 of MCP Secure.

| | |
|---|---|
| Model | `microsoft/unixcoder-base` + LoRA (r 32, α 64; query/key/value/dense), multi-label head |
| Classes | `cmdi` command injection (CWE-78), `path` path traversal (CWE-22), `ssrf` (CWE-918), `codei` code injection (CWE-94), `sqli` SQL injection (CWE-89), `deser` unsafe deserialization (CWE-502) |
| Languages | Python, TypeScript, JavaScript |
| Input | one function; 510-token windows (stride 256); function score = max over windows |
| Output | per-class score, mapped per class onto the marketplace scale (review 0.40, fail 0.75) |
| Model hash | `3276ec2589353ac40171c4881ef68e0e5802d3ece2c85be596a9fa65168c7289` (`python model_b.py hash`) |
| Training run | Kaggle `muhammadtalhaqamar/model-b-v8` v8 (T4, ~2 h 50 min), dataset `muhammadtalhaqamar/model-b-v8-data` |

## Training data

Real, pre-labelled vulnerable/fixed function pairs from security advisories (GitHub Security
Advisories / OSV fix commits), SVEN, GHSA MCP CVEs and a hand-curated MCP set. Every pair was
reviewed by hand. A pair was kept only when the vulnerable function itself contains the flaw;
pairs where the fix was elsewhere, the change was incidental, or the reviewer was unsure were
dropped, and wrong-class pairs were relabelled.

| split | functions | vulnerable | repos |
|---|---|---|---|
| train pool | 29,058 | 1,213 | 694 |
| synthetic (train only) | 1,280 | 640 cmdi | – |
| test_mcp_new (real MCP servers) | 161 | 81 | 25 |
| test_v6 | 45 | 23 | 19 |
| test_fresh_cmdi | 21 | 12 | 6 |
| wild (unlabelled MCP servers) | 23,010 | – | 46 |

Vulnerable functions per class in the train pool: cmdi 268, path 443, ssrf 145, codei 122,
sqli 128, deser 107. Safe functions: 24,636 ordinary MCP-server functions, 2,019 functions that use
a risky API with literal arguments only, 1,124 fixed twins. At most 12 pairs per repository per class.
Test and wild repositories are disjoint from training; no exact or near duplicates across splits.

## Evaluation

**Out-of-fold** (3 repository-grouped folds; each function scored by a model that never saw its repo):

| class | PR-AUC | fail: precision / recall | review: precision / recall | vuln scored above its fix |
|---|---|---|---|---|
| cmdi | 0.88 | 76% / 93% | 61% / 96% | 96% |
| path | 0.69 | 70% / 58% | 52% / 85% | 81% |
| ssrf | 0.63 | 74% / 17% | 50% / 74% | 76% |
| codei | 0.83 | 71% / 86% | 57% / 92% | 87% |
| sqli | 0.78 | 71% / 69% | 51% / 89% | 89% |
| deser | 0.82 | 71% / 88% | 50% / 99% | 89% |

Per-class thresholds were tuned on these out-of-fold scores (fail: best F2 with precision ≥ 70% and
≤ 0.5% of ordinary code flagged; review: lowest threshold with precision ≥ 50%).

**Held-out test sets** (final model, function level):

| set | at fail: precision / recall | at review: precision / recall |
|---|---|---|
| test_mcp_new | 86% / 52% | 72% / 78% |
| test_v6 | 92% / 100% | 85% / 100% |
| test_fresh_cmdi | 100% / 92% | 100% / 92% |

test_mcp_new per class, recall at review: cmdi 4/4, path 17/25, ssrf 10/18, codei 3/5, sqli 28/29
(no deser positives).

**Versus v8.1** on the same test functions: recall at fail 35% → 51%, at review 62% → 77%;
precision at fail 90% → 85%, at review 86% → 71%. Ranking quality on real MCP servers is about the
same (any-vulnerability AP 0.81 → 0.82); ssrf ranks better (PR-AUC 0.45 → 0.54), path slightly worse
(0.59 → 0.54).

**Wild MCP code** (23,010 unlabelled functions, 46 servers): 9.3% of functions reach fail and 21%
reach review; path accounts for most of it (6.3% at fail). A sample of these flags is mostly
internal file handling with no attacker input, so treat them as false alarms.

## How the marketplace uses it

Model B scores each function on its own and cannot see whether tool input reaches the risky call.
Used directly (server score = highest function score), it would FAIL 41 of the 46 wild servers.
So `ruleset.json` → `modelBPolicy` combines it with the AST taint analyzer at the policy layer:

- a Model B finding keeps its full score, and can FAIL the server, only when the AST analyzer reports
  a medium/high taint flow of the matching category in the same function;
- otherwise a fail-level score counts as 0.55 (REVIEW) and a review-level score as 0.25 (evidence).

Simulated on the evaluation data (AST run on the Python functions, every function analysed):

| set | vulnerable flagged (FAIL + REVIEW) | safe flagged |
|---|---|---|
| test_mcp_new | 48 / 81 (2 FAIL) | 8 / 80 |
| test_v6 | 23 / 23 (9 FAIL) | 2 / 22 |
| test_fresh_cmdi | 11 / 12 | 0 / 9 |
| AST alone, test_mcp_new | 8 / 81 | 2 / 80 |

Wild servers under this policy: 19 FAIL, 22 REVIEW, 5 PASS of 46. The FAILs come from AST HIGH
findings (every function was analysed and every parameter treated as tainted, which over-states the
marketplace, where only tool functions are analysed) and from AST + Model B agreeing.

## Limitations

- Function level only: no data flow across functions or files. Exploitability is the AST analyzer's
  job, and FAIL needs its corroboration, which today exists for Python only and not for ssrf or sqli.
  JS/TS servers and ssrf/sqli findings therefore reach REVIEW at most.
- Path traversal is the weakest real-world class: it flags ordinary file handling.
- Small per-class test sets on real MCP code (cmdi 4, codei 5, deser 0); those numbers are noisy.
- Positives come mostly from non-MCP open-source projects, ordinary negatives from MCP servers;
  test_mcp_new and the wild set are the checks for that shortcut.
- One reviewer labelled the pairs.
- More synthetic cmdi examples (640) than real ones (268).

## Reproduce

```bash
python release.py <kaggle-output-dir>   # copies the model, parity check (CPU vs Kaggle), ruleset hash
python parity_check.py                  # worst |CPU − Kaggle| 0.0001 over 227 test functions
python model_b.py scan path/to/repo     # scan a local repository
```
