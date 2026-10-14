# Model B scan service

Production inference for **Model B v8**, the MCP Secure code-vulnerability classifier
(UniXcoder + LoRA). It scores every function of an MCP server for six vulnerability classes and
returns a marketplace-scale score (review ≥ 0.40, fail ≥ 0.75). See `MODEL_CARD.md` for what the
model can and cannot do, with its measured accuracy.

| class | CWE |
|---|---|
| command injection | CWE-77/78 |
| path traversal | CWE-22 |
| SSRF | CWE-918 |
| code injection | CWE-94/95 |
| SQL injection | CWE-89 |
| unsafe deserialization | CWE-502 |

Tool poisoning and prompt-manipulation in descriptions are Model A's job; hardcoded secrets and
missing authentication are rule-based checks.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
(cd js && npm install)          # TypeScript compiler, used to parse TS/JS
```

The first start downloads the base model `microsoft/unixcoder-base` (pinned commit, about 500 MB)
from Hugging Face. After that it runs offline (`HF_HUB_OFFLINE=1`).

## Run

```bash
python serve.py --port 8765                    # HTTP service
python model_b.py scan path/to/server-repo     # one-off scan from the terminal
python model_b.py hash                         # model hash (goes into ruleset.json)
python parity_check.py                         # local scores == Kaggle scores? (needs the v8 dataset, MODEL_B_DATA)
```

### API

`GET /health` returns the model version, model hash, classes and thresholds.

`POST /scan` takes any mix of these inputs:

```json
{
  "markdown": "server description with ```python code blocks```",
  "code": "def f(x): ...", "language": "python",
  "files": [{"path": "src/server.ts", "content": "..."}],
  "github_url": "https://github.com/owner/repo", "ref": "main"
}
```

It returns:

```json
{
  "analyzer": "MODEL_B_CODE", "model_version": "model-b-v8", "model_hash": "…",
  "score": 0.99, "verdict_hint": "FAIL", "threat": "command_injection",
  "n_functions": 22, "n_flagged": 2,
  "evidence": ["command_injection (CWE-78) in run_command at server.py:3 score 0.99"],
  "findings": [{"file": "...", "func_name": "...", "start_line": 3, "score": 0.99,
                "class": "cmdi", "calibrated": {...}, "raw": {...}}],
  "sources": ["github https://github.com/owner/repo@<sha>"]
}
```

`score` is the highest function score. `findings` lists every function scored at least 0.40.

## Marketplace

The service also speaks the MCP Secure analyzer contract (spec §6): `GET /v1/health` and
`POST /v1/analyze` (alias `POST /api/predict/code`, as on the proposal slides). The marketplace
uses only these. `npm start` launches the service from `.venv` automatically when it is not
already running on `MODEL_B_URL` (default `http://127.0.0.1:8765`).

`/v1/analyze` receives the AnalysisBundle that ingestion built (the repository is cloned once, at a
pinned commit, by the marketplace; this service no longer clones it). It scores every function in
the bundle's code files and returns one finding per (function, class) at review level or above.
Each finding has its real file, line and function span, plus the `tool_id` when the function is an
MCP tool handler.

`score` / `verdict_hint` from `/scan` are Model B on its own. In the marketplace, the policy
(`ruleset.json`, rule `model_b_requires_corroboration`) lets a finding FAIL a server only when the
AST analyzer reports a medium/high flow of the same threat in an overlapping function of the same
file. Otherwise Model B can raise a server to REVIEW at most. See `MODEL_CARD.md` for why.

- If the service is not running, or errors, the slot reports it and the policy refuses to PASS
  (fail-closed). There is no simulated fallback for Model B.
- The ruleset pins the released model hash (`analyzerPins.model_b`). A different model cannot decide
  a PASS until it is released with `release.py`.
- Contract check: `npm run conformance -- --url http://127.0.0.1:8765` from the repository root.

## Releasing a new model

```bash
python release.py <kaggle-output-dir>   # copy files, parity check, pin the hash in ruleset.json
```

## Determinism and speed

- **Determinism:** inference runs on CPU in float32 with a fixed thread count and
  `torch.use_deterministic_algorithms`. Windows are batched only with windows of the same length,
  with no padding, so a function's score never depends on the rest of the scan. Scores are rounded
  to 4 decimals. The same input gives byte-identical output (checked).
- **Matches training:** text prep, windows and calibration are copies of the training code.
  `parity_check.py` confirms the local scores equal the Kaggle ones (max difference 0.0001).
- **Speed** (Apple-silicon Mac, 8 threads):

  | Input | Time |
  |---|---|
  | Per function | about 0.08–0.3 s |
  | 22-function server | 2 s |
  | 700-function repo | about 55 s (identical functions are scored once) |
