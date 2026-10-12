"""
Text preparation for Model B inference: an exact copy of dataset_v8/textprep.py (the rules the
model was trained with), except that TS payloads go through per-call temp files.

Original header: text preparation shared by the v8 dataset builder. Same rules as the v6 builder
(model_b_dataset/build_model_b_dataset.py), packaged as functions so they can be imported:

  normalized_code  Python: dedented if needed to parse; TS/JS: wrapped in a throwaway class if a
                   bare method only parses that way (checked with the real TS compiler).
  model_code       normalized_code with every comment removed (fix commits annotate themselves,
                   e.g. "// prevent shell injection", which would leak the label). Falls back to
                   normalized_code if stripping breaks parsing.
  focus_spans      for vulnerable rows with a fixed twin: [start, end] character ranges in
                   model_code of lines that the fix removed or changed.
"""
import ast
import collections
import io
import json
import os
import re
import subprocess
import tempfile
import textwrap
import tokenize
from pathlib import Path

TSDIR = Path(__file__).resolve().parent / "js"

_NORMALIZE_JS = r"""
const ts = require('typescript'); const fs = require('fs');
const items = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const printer = ts.createPrinter({ removeComments: true });
const bad = sf => (sf.parseDiagnostics || []).length > 0;
const out = items.map(it => {
  let code = it.code, ok = true;
  if (bad(ts.createSourceFile('x.ts', code, ts.ScriptTarget.Latest, true))) {
    const w = 'class __ModelBWrap {\n' + code + '\n}';
    if (!bad(ts.createSourceFile('x.ts', w, ts.ScriptTarget.Latest, true))) code = w; else ok = false;
  }
  let stripped = null;
  if (ok) {
    const sf = ts.createSourceFile('x.ts', code, ts.ScriptTarget.Latest, true);
    const printed = printer.printFile(sf);
    if (!bad(ts.createSourceFile('x.ts', printed, ts.ScriptTarget.Latest, true))) stripped = printed;
  }
  return { id: it.id, normalized: code, ok, stripped };
});
process.stdout.write(JSON.stringify(out));
"""


def _dedent_python(code):
    for c in (code, textwrap.dedent(code)):
        try:
            ast.parse(c)
            return c, True
        except Exception:
            pass
    return code, False


def _strip_py_comments(code):
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(code).readline))
    except Exception:
        return None
    lines = code.split("\n")
    for t in reversed([t for t in toks if t.type == tokenize.COMMENT]):
        (r, c), (_, ec) = t.start, t.end
        lines[r - 1] = (lines[r - 1][:c] + lines[r - 1][ec:]).rstrip()
    out = re.sub(r"\n\s*\n(\s*\n)+", "\n\n", "\n".join(lines))
    try:
        ast.parse(out)
    except Exception:
        return None
    return out


def _ts_batch(items, chunk=1500):
    script = TSDIR / "normalize_strip_v8.js"
    if not script.exists() or script.read_text(encoding="utf-8") != _NORMALIZE_JS:
        script.write_text(_NORMALIZE_JS, encoding="utf-8")
    res = {}
    for i in range(0, len(items), chunk):
        part = items[i:i + chunk]
        # per-call temp file (the scan service may run several scans at once)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tf:
            json.dump([{"id": r["id"], "code": r["code"]} for r in part], tf)
        try:
            p = subprocess.run(["node", str(script), tf.name], capture_output=True, text=True, timeout=900)
            for it in json.loads(p.stdout):
                res[it["id"]] = it
        except Exception as e:
            print(f"[textprep] TS batch {i} failed: {e}")
        finally:
            os.unlink(tf.name)
    return res


def prepare(rows):
    """Adds normalized_code, parses_standalone and model_code to every row (in place)."""
    stats = collections.Counter()
    ts_rows = [r for r in rows if r["language"] in ("typescript", "javascript")]
    ts_res = _ts_batch(ts_rows) if ts_rows else {}
    for r in rows:
        if r["language"] == "python":
            norm, ok = _dedent_python(r["code"])
            stripped = _strip_py_comments(norm) if ok else None
        elif r["language"] in ("typescript", "javascript"):
            it = ts_res.get(r["id"])
            norm, ok, stripped = (it["normalized"], it["ok"], it["stripped"]) if it else (r["code"], None, None)
        else:
            norm, ok, stripped = r["code"], None, None
        r["normalized_code"], r["parses_standalone"] = norm, ok
        r["model_code"] = stripped if stripped else norm
        stats[f"{r['language']}:{'stripped' if stripped else 'fallback'}"] += 1
    return stats


def _line_spans(code):
    spans, pos = [], 0
    for line in code.split("\n"):
        spans.append((pos, pos + len(line), line.strip()))
        pos += len(line) + 1
    return spans


def _merge(spans):
    out = []
    for a, b in sorted(spans):
        if out and a <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return out


def focus_from_twin(vuln_code, fixed_code):
    """Lines of the vulnerable version that do not appear in the fixed version."""
    fixed = collections.Counter(l for _, _, l in _line_spans(fixed_code) if l)
    spans = [[a, b] for a, b, l in _line_spans(vuln_code) if l and fixed[l] == 0]
    return _merge(spans) if spans else None
