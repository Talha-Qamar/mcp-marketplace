#!/usr/bin/env python3
"""
Model B scan service (HTTP, JSON). Standard library server; one model instance, scans serialized.

  GET  /health   -> {status, model_version, model_hash, classes, thresholds}
  POST /scan     body (any combination; all sources are merged):
                   {"markdown": "..."}                 code blocks inside a server description
                   {"code": "...", "language": "python"}
                   {"files": [{"path": "src/x.ts", "content": "..."}]}
                   {"github_url": "https://github.com/owner/repo", "ref": "<branch|tag|sha>"}
                 -> {analyzer, model_version, model_hash, score, verdict_hint, threat, evidence, findings, ...}

Scores are on the marketplace scale (review >= 0.40, fail >= 0.75; ruleset.json).

MCP Secure analyzer contract (spec section 6), served alongside the endpoints above:
  GET  /v1/health                      -> contracts/analyzer-health.schema.json
  POST /v1/analyze  {"bundle": {...}}  -> contracts/analyzer-result.schema.json
  POST /api/predict/code               alias of /v1/analyze (proposal slide 7)

Usage: python serve.py [--host 127.0.0.1] [--port 8765]
"""
import argparse
import json
import re
import shutil
import sys
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import model_b

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "services" / "analyzer_kit"))
import analyzer_kit as kit  # noqa: E402

CONTRACT_ID = "model_b"
CONTRACT_PATHS = ("/v1/analyze", "/api/predict/code")
CODE_LANGS = ("python", "typescript", "javascript")

MAX_BODY = 20 * 1024 * 1024
GITHUB_RE = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")
REF_RE = re.compile(r"^[A-Za-z0-9_./-]{1,200}$")
FENCE_RE = re.compile(r"```[ \t]*([A-Za-z0-9_+-]*)[^\n]*\n(.*?)```", re.S)
LANG_ALIAS = {"py": "python", "python": "python", "python3": "python", "js": "javascript",
              "javascript": "javascript", "node": "javascript", "mjs": "javascript",
              "ts": "typescript", "typescript": "typescript", "tsx": "typescript"}
EXT = {"python": ".py", "javascript": ".js", "typescript": ".ts"}


def guess_language(code):
    try:
        import ast
        ast.parse(code)
        return "python" if re.search(r"^\s*(def|class|import|from)\s", code, re.M) else None
    except Exception:
        pass
    if re.search(r"\b(function|const|let|=>|require\(|import .* from)\b", code):
        return "typescript" if re.search(r":\s*(string|number|boolean|any)\b|interface\s", code) else "javascript"
    return None


def markdown_snippets(md):
    """Code blocks in a server description: fenced blocks, plus an unfenced 'Code Implementation'
    section (the marketplace's bait-and-switch demo uses one)."""
    out = []
    for tag, body in FENCE_RE.findall(md or ""):
        lang = LANG_ALIAS.get(tag.lower()) or guess_language(body)
        if lang:
            out.append((lang, body))
    stripped = FENCE_RE.sub("", md or "")
    m = re.search(r"^#+\s*Code Implementation\s*$(.*?)(?=^#{1,3}\s|\Z)", stripped, re.M | re.S)
    if m and m.group(1).strip():
        lang = guess_language(m.group(1).strip())
        if lang:
            out.append((lang, m.group(1).strip()))
    return out


def snippet_functions(snippets):
    files = [{"path": f"snippet_{i}{EXT[lang]}", "content": code} for i, (lang, code) in enumerate(snippets)]
    funcs = model_b.extract_files(files)
    have = {f["file"] for f in funcs}
    for f in files:   # a snippet without any function is scored as one unit
        lang = next(l for l, e in EXT.items() if f["path"].endswith(e))
        if f["path"] not in have and f["content"].count("\n") >= 2:
            funcs.append({"file": f["path"], "func_name": "<snippet>", "language": lang,
                          "start_line": 1, "end_line": f["content"].count("\n") + 1, "code": f["content"]})
    return funcs


def github_functions(url, ref=None):
    m = GITHUB_RE.match(url or "")
    if not m:
        raise ValueError("github_url must look like https://github.com/<owner>/<repo>")
    if ref and not REF_RE.match(ref):
        raise ValueError("invalid ref")
    d = Path(tempfile.mkdtemp(prefix="modelb_"))
    env = {"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "true", "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}
    try:
        git = ["git", "-c", "credential.helper=", "-c", "credential.interactive=false"]
        if ref:
            subprocess.run(git + ["init", "-q", str(d)], check=True, env=env, timeout=30)
            subprocess.run(git + ["-C", str(d), "remote", "add", "origin", f"https://github.com/{m[1]}/{m[2]}.git"],
                           check=True, env=env, timeout=30)
            r = subprocess.run(git + ["-C", str(d), "fetch", "-q", "--depth", "1", "origin", ref],
                               capture_output=True, text=True, env=env, timeout=300)
            if r.returncode == 0:
                r = subprocess.run(git + ["-C", str(d), "checkout", "-q", "FETCH_HEAD"],
                                   capture_output=True, text=True, env=env, timeout=120)
        else:
            r = subprocess.run(git + ["clone", "-q", "--depth", "1", f"https://github.com/{m[1]}/{m[2]}.git", str(d)],
                               capture_output=True, text=True, env=env, timeout=300)
        if r.returncode != 0:
            raise LookupError(f"could not fetch {m[1]}/{m[2]}: {r.stderr.strip()[:200]}")
        sha = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        return model_b.extract_dir(d), sha
    finally:
        shutil.rmtree(d, ignore_errors=True)


def contract_identity(m):
    return {"id": CONTRACT_ID, "version": model_b.MODEL_VERSION, "artifact_hash": "sha256:" + m.hash, "engine": "model"}


def contract_health(m):
    return {
        **contract_identity(m),
        "display_name": "Model B — code classifier",
        "description": "UniXcoder + LoRA; scores every function for six vulnerability classes",
        "consumes": ["files", "tools"],
        "languages": list(CODE_LANGS),
        "threats": sorted({model_b.CLASS_INFO[c][0] for c in m.classes}),
        "contract_version": kit.CONTRACT_VERSION,
    }


def contract_analyze(m, bundle):
    """Score every function in the bundle's code files; one finding per (function, class) at review level or above."""
    code = [{"path": f["path"], "content": f["content"]} for f in bundle.get("files", []) if f.get("language") in CODE_LANGS]
    if not code:
        return kit.result(contract_identity(m), "not_applicable", notes=["no Python/TypeScript/JavaScript source in bundle"])
    # Ingestion already selected the files: no re-filtering. The model was
    # trained on functions of 3+ lines; here 2-line functions are scored too
    # (`def f(x): return os.system(x)` is a whole helper), and one-liners only
    # when they are an MCP tool handler, so short code cannot slip past.
    funcs = [f for f in model_b.extract_files(code, apply_filters=False, min_newlines=0)
             if f["code"].count("\n") >= 1
             or kit.tool_for_span(bundle, f["file"], f.get("start_line") or 1, f.get("end_line") or f.get("start_line") or 1)]
    scored = m.score_functions(funcs)
    findings = []
    for r in scored:
        start, end = r.get("start_line") or 1, r.get("end_line") or r.get("start_line") or 1
        tool_id = kit.tool_for_span(bundle, r["file"], start, end)
        for cls in m.classes:
            s = r["calibrated"][cls]
            if s < model_b.REVIEW_CAL:
                continue
            threat, cwe = model_b.CLASS_INFO[cls]
            findings.append({
                "finding_id": kit.finding_id(CONTRACT_ID, r["file"], start, r["func_name"], cls),
                "threat": threat,
                "cwe": cwe,
                "score": float(s),
                "severity": "high" if s >= model_b.FAIL_CAL else "medium",
                "location": {"file": r["file"], "line": start,
                             "function": {"name": r["func_name"], "start_line": start, "end_line": end},
                             "tool_id": tool_id},
                "summary": "%s (%s) in %s, model score %.2f" % (threat, cwe, r["func_name"], s),
                "details": {"class": cls, "raw": r["raw"][cls], "calibrated": r["calibrated"]},
            })
    langs = sorted({f["language"] for f in funcs}) or sorted({f.get("language") for f in bundle.get("files", []) if f.get("language") in CODE_LANGS})
    return kit.result(contract_identity(m), "ok", findings, units_total=len(funcs), units_analyzed=len(scored),
                      languages=langs, notes=[] if funcs else ["no functions of 3+ lines to score"])


class Handler(BaseHTTPRequestHandler):
    model = None
    lock = threading.Lock()

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        try:  # best effort: a closed stdout (parent crashed) must not drop the response
            print("[model-b]", self.address_string(), fmt % args, flush=True)
        except (OSError, ValueError):
            pass

    def do_GET(self):
        if self.path == "/v1/health":
            return self._send(200, contract_health(self.model))
        if self.path != "/health":
            return self._send(404, {"error": "not found"})
        m = self.model
        self._send(200, {"status": "ok", "model_version": model_b.MODEL_VERSION, "model_hash": m.hash,
                         "classes": m.classes, "thresholds_raw": {"fail": m.fail, "review": m.review},
                         "marketplace_thresholds": {"review": model_b.REVIEW_CAL, "fail": model_b.FAIL_CAL}})

    def do_POST(self):
        if self.path in CONTRACT_PATHS:
            return self._contract_post()
        if self.path != "/scan":
            return self._send(404, {"error": "not found"})
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > MAX_BODY:
            return self._send(413 if n > MAX_BODY else 400, {"error": "body required (max 20 MB)"})
        try:
            req = json.loads(self.rfile.read(n))
        except Exception:
            return self._send(400, {"error": "invalid JSON"})
        funcs, sources = [], []
        try:
            if req.get("markdown"):
                sn = markdown_snippets(req["markdown"])
                funcs += snippet_functions(sn); sources.append(f"markdown ({len(sn)} code blocks)")
            if req.get("code"):
                lang = LANG_ALIAS.get(str(req.get("language", "")).lower()) or guess_language(req["code"]) or "python"
                funcs += snippet_functions([(lang, req["code"])]); sources.append("code")
            if req.get("files"):
                funcs += model_b.extract_files(req["files"]); sources.append(f"files ({len(req['files'])})")
            if req.get("github_url"):
                try:
                    gf, sha = github_functions(req["github_url"], req.get("ref"))
                    funcs += gf; sources.append(f"github {req['github_url']}@{sha[:12]}")
                except LookupError as e:
                    sources.append(f"github unavailable: {e}")
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        with self.lock:
            res = self.model.scan(funcs)
        res["sources"] = sources
        self._send(200, res)


    def _contract_post(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > MAX_BODY:
            return self._send(413 if n > MAX_BODY else 400, {"error": "body required (max 20 MB)"})
        try:
            bundle = json.loads(self.rfile.read(n))["bundle"]
        except Exception:
            return self._send(400, {"error": "body must be {\"bundle\": AnalysisBundle}"})
        try:
            with self.lock:
                res = contract_analyze(self.model, bundle)
        except Exception as e:
            res = kit.result(contract_identity(self.model), "error", error="%s: %s" % (type(e).__name__, e))
        self._send(200, res)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    a = ap.parse_args()
    Handler.model = model_b.ModelB()
    print(f"[model-b] {model_b.MODEL_VERSION} hash {Handler.model.hash[:16]}... listening on http://{a.host}:{a.port}",
          flush=True)
    ThreadingHTTPServer((a.host, a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
