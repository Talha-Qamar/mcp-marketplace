# AST Taint Analyzer — MCP Secure, Part 2

A deterministic static analyzer that decides whether attacker-controlled input can reach a
dangerous execution sink inside an MCP server's tool functions — i.e. **command injection**.

It parses Python into an AST, tracks which variables carry untrusted data, and checks whether
that data flows into a dangerous call. **It never executes, imports, compiles or evaluates the
code it analyses.**

Two consumers, so two outputs from one pass:

| Consumer | Output |
|---|---|
| Deterministic policy engine (Part 6) | A hard verdict with full evidence: sink, line, column, taint path, hops, severity, source line |
| Model B / GraphCodeBERT (Part 3) | A fixed-length, fixed-order numeric feature vector |

## What it explicitly does *not* do

- **No execution.** Parse only. No `exec`, no `eval`, no import of the target, no sandbox, no
  dynamic confirmation. This is what makes the analyzer safe to point at hostile third-party code.
- **No path sensitivity.** Both arms of an `if` are analysed and their taint states merged. A flow
  that only exists on an unreachable path is still reported.
- **No inter-procedural analysis.** Taint does not follow into helper functions. A call to an
  unknown free function returns a clean value.
- **No element-level alias analysis.** `lst[0] = tainted` taints the whole `lst`.
- **No ML.** Zero probabilistic components. Same bytes in, same bytes out, forever.

Over-approximation is deliberate. A borderline flag routes to REVIEW; a missed flow does not.

---

## Install and run

Standard library only at runtime — `pytest` is needed for the test suite and nothing else.

```bash
cd ast_taint_analyzer
python -m pip install -e ".[dev]"     # or: set PYTHONPATH=src
```

```bash
# analyse one file, human-readable
python -m ast_taint scan path/to/server.py

# analyse a repo, JSON out (for the dataset pipeline)
python -m ast_taint scan path/to/repo --json --out results.json

# emit feature vectors only (for Model B training)
python -m ast_taint features path/to/repo --out features.jsonl

# analyse every function, not just @tool-decorated ones
python -m ast_taint scan path/to/repo --all-functions

# print the frozen feature contract
python -m ast_taint feature-names
```

Exit code `0` when no HIGH severity finding was produced, `1` when at least one was — usable as a
CI gate. `2` is reserved for usage and IO errors.

```bash
python -m pytest                      # the suite
python -m pytest --cov=ast_taint      # with coverage
python scripts/eval_fixtures.py       # confusion matrix over all 36 fixtures
```

### As an MCP Secure analyzer service

```bash
python ast_taint_analyzer/service.py --port 8701     # from the repository root
```

`service.py` wraps the engine, unchanged, in the analyzer contract (`GET /v1/health`,
`POST /v1/analyze`; spec §6). It analyses the Python tool handlers that ingestion discovered, and
analyses every function only in files without decorated tools. Each sink hit becomes a finding in the
shared taxonomy: shell → `command_injection`, exec/dynamic → `code_injection`, file →
`path_traversal`, deserialize → `unsafe_deserialization`. Hits carry real file, line and function
spans. `artifact_hash` is the SHA-256 of `config.py`. The marketplace starts the service itself on
`npm start`; `tests/test_service.py` covers the wrapper.

### Library use

```python
from ast_taint import analyze_file, to_feature_vector

analysis = analyze_file("server.py")
for tool in analysis.tools:
    print(tool.tool_name, tool.max_severity.value, to_feature_vector(tool))
    for hit in tool.hits:
        print("   ", hit.render_flow(), "at line", hit.lineno)
```

`analyze_source`, `analyze_file` and `analyze_repo` are pure functions with no global mutable
state. `analyze_repo` skips `venv/`, `.venv/`, `env/`, `.git/`, `__pycache__/`, `tests/`,
`site-packages/`, `node_modules/`, `build/`, `dist/` and the usual cache directories. The skip
list applies to *child* directories only, so pointing it straight at a `tests/` folder still works.

---

## Sink registry

Everything the analyzer knows lives in `src/ast_taint/config.py` as data, not logic. If a reviewer
asks "what exactly do you detect?", that is the one file to open.

| Sink | Category | Dangerous args | Condition |
|---|---|---|---|
| `os.system` | shell | 0 | — |
| `os.popen` | shell | 0 | — |
| `os.execv`, `os.execve` | shell | 0, 1 | — |
| `os.spawnl` | shell | 1 | — |
| `subprocess.run` | shell | 0, `args=` | only with `shell=True` |
| `subprocess.call` | shell | 0, `args=` | only with `shell=True` |
| `subprocess.check_call` | shell | 0, `args=` | only with `shell=True` |
| `subprocess.check_output` | shell | 0, `args=` | only with `shell=True` |
| `subprocess.Popen` | shell | 0, `args=` | only with `shell=True` |
| `commands.getoutput` | shell | 0 | — |
| `eval`, `exec`, `compile` | exec | 0 | — |
| `getattr`, `setattr` | dynamic | 1 | — |
| `__import__`, `importlib.import_module` | dynamic | 0 | — |
| `pickle.load`, `pickle.loads` | deserialize | 0 | — |
| `marshal.loads` | deserialize | 0 | — |
| `yaml.load` | deserialize | 0 | only without `Loader=SafeLoader`/`CSafeLoader` |
| `open` | file | 0, `file=` | — |
| `pathlib.Path` | file | 0 | — |

**Sanitizers** — `shlex.quote`, `shlex.split`, `pipes.quote`, `re.escape`, `urllib.parse.quote`,
`os.path.basename`, `html.escape`. A sanitizer on the path marks the hit `sanitized=True` and
drops it to LOW. The hit is **not** suppressed: the flow is still real, and a human (or Model C)
should see that tool input reached a shell even in quoted form.

**Taint sources** — every parameter of the tool function (the dominant source; MCP tool arguments
are attacker-controlled by definition), plus `input()`, `sys.argv[...]`, `os.environ[...]`,
`os.environ.get`, `os.getenv`, and `json.loads` when its own argument is already tainted.

**Tool decorators** — matched on the final attribute segment, so `@tool`, `@mcp.tool()`,
`@server.tool(name="x")`, `@a.b.c.tool()` and `@FastMCP("x").tool()` all match. `register_tool`
and `function_tool` are recognised too. `--all-functions` is the fallback for repositories that
do not use decorators.

**Alias resolution** — `import os as o` and `from os import system` both resolve to `os.system`
before the registry lookup. A one-token rename does not defeat the analyzer.

### Severity

```
HIGH    = unsanitized, SHELL or EXEC category, hops <= 2
MEDIUM  = unsanitized and (hops > 2 or category in {DYNAMIC, DESERIALIZE, FILE})
LOW     = sanitized (any category)
NONE    = no hits
```

`n_hops` counts assignments from the originating parameter to the sink, inclusive of the final
step into the call, so a parameter used directly is 1 hop.

---

## Feature vector contract — **FROZEN**

Model B concatenates this into its classification head. **The names, their order and their ranges
must never change once Model B has been trained**, or its learned weights stop meaning anything.
Adding a feature means retraining Model B. `tests/test_features.py` pins the order literally so a
reordering shows up as a diff in the test file, not as a mysterious accuracy drop months later.

| # | Name | Range |
|---|---|---|
| 0 | `reaches_sink` | 0/1 |
| 1 | `n_hits` | 0–10 (capped) |
| 2 | `min_hops` | 0–10 (capped; 0 when there are no hits) |
| 3 | `max_severity` | 0=none, 1=low, 2=medium, 3=high |
| 4 | `has_shell_sink` | 0/1 |
| 5 | `has_exec_sink` | 0/1 |
| 6 | `has_dynamic_sink` | 0/1 |
| 7 | `has_file_sink` | 0/1 |
| 8 | `has_deserialize_sink` | 0/1 |
| 9 | `any_sanitized` | 0/1 |
| 10 | `all_sanitized` | 0/1 (0 when there are no hits) |
| 11 | `n_params` | 0–10 (capped) |
| 12 | `n_tainted_vars` | 0–20 (capped) |
| 13 | `has_fstring_flow` | 0/1 |
| 14 | `has_concat_flow` | 0/1 |
| 15 | `shell_true_present` | 0/1 |

Values are left **raw** (only capped). Scaling belongs in the model's preprocessing, not in the
analyzer. `has_fstring_flow` / `has_concat_flow` record that tainted data passed through an
f-string or a `+` concatenation **anywhere in the function**, whether or not that particular flow
reached a sink. `shell_true_present` records that a `subprocess` call used `shell=True` at all,
independent of taint.

### `label_hint` is a candidate label, not ground truth

The `features` subcommand emits `"label_hint": "injection" | "benign"`, derived mechanically from
`reaches_sink`. **Training Model B directly on these would be circular labelling** — the model
would learn to imitate this scanner, including its blind spots. The project's design routes
candidate labels through Model C, which audits them against separately-sourced evidence before
they are promoted to ground truth, and escalates `uncertain` to a human rather than into the
training set.

---

## Determinism

Same input → byte-identical output, every time. This is a product property, not a nicety: the
attestation MCP Secure signs binds a verdict to a fingerprint, so a verdict that could vary would
make the signature meaningless.

How it is enforced:

- Every collection on a result object is a `tuple`; every internal list is sorted by a stable key
  (`lineno`, `col_offset`, `sink_name`, arg index, arg name) before being frozen.
- No timestamps, object ids, or iteration over unordered sets in anything that reaches the output.
- Branch merges pick a winner by a total order (`sanitized`, `hops`, `path`, `origin`), so the
  result does not depend on the order the arms were visited.
- `tests/test_determinism.py` runs each fixture 50 times and compares serialised JSON, and
  re-runs the whole fixture directory in fresh interpreters under `PYTHONHASHSEED` ∈
  {0, 1, 42, 12345, random}, comparing SHA-256 of the output.
- Loop analysis runs a bounded fixpoint (max 4 passes) with findings suppressed, then records in
  exactly one final pass, so hit lists never depend on how many passes convergence took.

---

## Known limitations

Stated honestly, because a defence panel will find them anyway:

1. **Over-approximates on branches.** Both arms of an `if`/`try` are analysed and merged, so a
   flow that cannot actually execute may still be reported.
2. **No inter-procedural analysis.** `cmd = build_command(q); os.system(cmd)` is *not* flagged —
   taint does not follow into `build_command`, in this file or any other. This is the single
   largest detection gap, and the main reason Model B exists alongside the analyzer.
3. **No element-level alias analysis.** `lst[0] = tainted` taints the whole container; conversely
   assigning a clean value into one slot does not clear the container's taint.
4. **Taint entering by dynamic attribute access is invisible.** `setattr(obj, name, tainted)`
   followed by `getattr(obj, name)` is not tracked.
5. **Subscript taint follows the base, not the index.** `TABLE[user_choice]` stays clean, which is
   correct (the value comes from a trusted table) and is what keeps allowlist-validated tools out
   of the findings — but a genuinely tainted dict built elsewhere and indexed cleanly can hide.
6. **Conservative where it cannot decide.** An unresolvable `shell=` expression, or a
   `subprocess` call receiving `**kwargs`, is treated as `shell=True`. This can produce a false
   positive; the alternative is a silent miss.
7. **Expression depth is capped** at 100 levels and **loop fixpoints at 4 passes**. Pathological
   generated code beyond those bounds is under-analysed rather than crashing the scanner.
8. **Module-wide alias map.** Imports are collected across the whole module, including imports
   nested inside functions, so a local `import os as o` in one function resolves names in another.
   Over-approximate, and harmless in practice.
9. **Relative imports are not resolved** (`from .utils import run` yields no stable dotted name),
   so a sink re-exported through a relative import is missed.

---

## Test suite

36 fixtures, built before the engine so the engine was written against real targets.

| Group | Count | Contract |
|---|---|---|
| `tests/fixtures/vulnerable/` | 20 | Must be flagged, with the exact severity, hop count, sink category and sanitized flag recorded in `expectations.json` |
| `tests/fixtures/safe/` | 10 | Must produce **zero** hits |
| `tests/fixtures/edge/` | 6 | Must be handled without an exception |

`tests/fixtures/expectations.json` is the single source of truth, loaded by both the unit tests
and `scripts/eval_fixtures.py`, so the suite and the metrics report can never disagree about what
"correct" means.

The suite also covers alias resolution, conditional sinks, every propagation rule, untainting,
the severity table, repository walking, the CLI's four documented invocations and its exit codes.

---

## Documented decisions

Judgement calls made while implementing the plan, recorded so they can be challenged:

- **Sanitized severity.** Plan §3.2 says a sanitizer drops severity one level (HIGH → MEDIUM);
  plan §5.5 and vulnerable fixture 20 say a sanitized flow is LOW. The §5.5 table wins, since it
  is the normative severity definition and the fixture pins it.
- **`ToolAnalysis` carries two extra fields** beyond the plan's dataclass: `docstring` (the tool
  description, which Model A consumes — the same extraction pass produces both views of a tool)
  and `flow_facts`. `flow_facts` is required: `n_tainted_vars`, `has_fstring_flow`,
  `has_concat_flow` and `shell_true_present` are in the frozen feature vector but are not
  derivable from `hits` alone. Both have defaults, so the plan's construction order still works.
- **`n_hops` includes the step into the sink**, making a directly-used parameter 1 hop. This is
  what the plan's own fixture table requires (case 1 → 1 hop, case 3 → 2 hops, case 4 → MEDIUM).
- **`__main__.py` and a `feature-names` subcommand** were added; the former is required for
  `python -m ast_taint` to work at all, the latter prints the frozen contract for the Part 3
  training code to assert against.
- **Edge fixture 3 is materialized at test time** rather than committed. It deliberately contains
  a byte (`0xFF`) that is not valid UTF-8, and a file like that does not survive a round trip
  through `git` autocrlf, most editors, or a GitHub diff view — storing it on disk makes the test
  quietly stop testing anything. `tests/fixture_support.py` builds it from an explicit bytes
  literal so the byte stays exact.
- **`--all-functions` does not descend into nested functions**, since those are already analysed
  as part of their enclosing function's body. Default (decorated) mode *does* descend, because
  FastMCP servers commonly register tools from inside `main()`.
- **Safe fixture 6 (allowlist) produces zero hits**, not a conservative flag. The plan allowed
  either; zero is correct here because taint follows the base of a subscript rather than its
  index, so a value drawn from a trusted constant table is genuinely not attacker data.
