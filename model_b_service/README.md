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

Start the service, then the marketplace with `MODEL_B_URL`:

```bash
MODEL_B_URL=http://127.0.0.1:8765 npm start
```

`../src/mcpsecure/engine.js` → `runScan()` sends each server's description, and its `github_url`
when that is a real public repo, to `/scan`. Model B's score enters the policy engine as
`MODEL_B_CODE`, and the scan record stores the service's model hash.

- Without `MODEL_B_URL`, the old simulated heuristic runs, and the record says
  `modelBMode: "simulated"`.
- If the service is configured but unreachable, the result is **REVIEW**, never a silent PASS.

## Releasing a new model

```bash
python release.py <kaggle-output-dir>   # copy files, parity check, write hash into ruleset.json
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
