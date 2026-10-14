#!/usr/bin/env python3
"""
Model B -- production inference for the MCP Secure code-vulnerability classifier (v8).

Classes (multi-label): cmdi (command injection, CWE-77/78), path (path traversal, CWE-22),
ssrf (CWE-918), codei (code injection, CWE-94/95), sqli (CWE-89), deser (unsafe
deserialization, CWE-502). Description-level threats (tool poisoning, PMA) are Model A's job.

Pipeline (identical to training, see kaggle_v8/train_v8.py):
  1. functions are extracted from .py / .ts / .js files (Python `ast`, real TS compiler);
  2. each function is normalized and stripped of comments (textprep.py);
  3. tokenized into 510-token windows (stride 256, at most 64 windows per function);
  4. per class, function score = max sigmoid over its windows;
  5. raw scores are mapped per class onto the marketplace scale (review 0.40, fail 0.75)
     with the thresholds tuned on out-of-fold data (model_b_config.json).

Determinism: CPU, float32, fixed thread count, eval mode (no dropout), windows batched only with
windows of the same length (no padding, so a function's score never depends on what else is in
the scan), scores rounded to 4 decimals.

Usage:
  python model_b.py scan <dir-or-file> [--json]
  python model_b.py hash
"""
import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import textprep  # noqa: E402

DEFAULT_MODEL_DIR = Path(os.environ.get("MODEL_B_DIR", HERE / "model_b_v8"))
EXTRACTOR = HERE / "js" / "extract_functions.js"
REVIEW_CAL, FAIL_CAL = 0.40, 0.75
MODEL_VERSION = "model-b-v8"
CACHE_MAX = 200_000   # cached per-function score rows (about 100 MB at most)
# base model pinned to an exact Hugging Face commit (part of the model hash)
BASE_REVISION = os.environ.get("MODEL_B_BASE_REVISION", "5604afdc964f6c53782a6813140ade5216b99006")

# same file filters as the corpus the model was evaluated on (corpus/build_corpus.py)
SKIP_DIR = re.compile(r"(^|/)(node_modules|dist|build|out|\.git|vendor|venv|\.venv|site-packages|__pycache__|"
                      r"tests?|__tests__|spec|e2e|examples?|docs?|fixtures?|coverage|\.next|bench\w*)(/|$)", re.I)
SKIP_FILE = re.compile(r"(\.d\.ts$|\.min\.js$|\.test\.|\.spec\.|_test\.py$|^test_.*\.py$|conftest\.py$|setup\.py$)")
CODE_SUFFIX = {".py": "python", ".ts": "typescript", ".tsx": "typescript",
               ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript"}
MAX_FILE_BYTES = 400_000
MAX_FUNC_CHARS = 60_000
MAX_FUNCS_PER_SCAN = 20_000

CLASS_INFO = {
    "cmdi": ("command_injection", "CWE-78"), "path": ("path_traversal", "CWE-22"),
    "ssrf": ("ssrf", "CWE-918"), "codei": ("code_injection", "CWE-94"),
    "sqli": ("sql_injection", "CWE-89"), "deser": ("unsafe_deserialization", "CWE-502"),
    "backdoor": ("backdoor", "CWE-506"),
}


# ---------------------------------------------------------------------------- extraction
def py_functions(src):
    try:
        tree = ast.parse(src)
    except Exception:
        return []
    lines = src.split("\n")
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.decorator_list[0].lineno if node.decorator_list else node.lineno
            out.append((node.name, "\n".join(lines[start - 1:node.end_lineno]), start, node.end_lineno))
    return out


def ts_functions(files):
    """files: [(path_on_disk, text)] -> {path: [(name, code, start, end)]} (one Node process per 300 files)."""
    res = {}
    paths = [str(p) for p, _ in files]
    for i in range(0, len(paths), 300):
        chunk = paths[i:i + 300]
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(chunk))
        try:
            p = subprocess.run(["node", str(EXTRACTOR), "--batch", tf.name], capture_output=True, text=True, timeout=600)
            data = json.loads(p.stdout) if p.returncode == 0 else {}
        except Exception:
            data = {}
        finally:
            os.unlink(tf.name)
        for p in chunk:
            res[p] = [(f.get("name") or "<anon>", f["text"], f.get("startLine"), f.get("endLine"))
                      for f in data.get(p, [])]
    return res


def extract_dir(root, apply_filters=True, min_newlines=2):
    """All functions under root, with the same filters as the evaluation corpus.

    apply_filters=False / min_newlines=0 are for the MCP Secure contract path,
    where ingestion has already chosen the files (including code it pulled back
    from tests/ or dist/ because the server runs it) and short tool handlers
    must not be dropped. The defaults keep evaluation behaviour unchanged."""
    root = Path(root)
    files = []
    targets = [root] if root.is_file() else sorted(root.rglob("*"))
    for f in targets:
        rel = f.name if root.is_file() else f.relative_to(root).as_posix()
        if not f.is_file() or f.suffix not in CODE_SUFFIX:
            continue
        if apply_filters and not root.is_file() and (SKIP_DIR.search(rel) or SKIP_FILE.search(f.name)):
            continue
        try:
            if f.stat().st_size > MAX_FILE_BYTES:
                continue
            files.append((f, rel, f.read_text(encoding="utf-8", errors="replace")))
        except Exception:
            continue
    ts = ts_functions([(f, t) for f, _, t in files if f.suffix != ".py"])
    funcs = []
    for f, rel, text in files:
        lang = CODE_SUFFIX[f.suffix]
        found = py_functions(text) if lang == "python" else ts.get(str(f), [])
        for name, code, s0, e0 in found:
            if not code or len(code) > MAX_FUNC_CHARS or code.count("\n") < min_newlines:
                continue
            funcs.append({"file": rel, "func_name": name, "language": lang, "start_line": s0,
                          "end_line": e0, "code": code})
    return funcs[:MAX_FUNCS_PER_SCAN]


def extract_files(files, apply_filters=True, min_newlines=2):
    """files: [{path, content}] (e.g. from an upload) -> functions. Written to a temp dir first."""
    with tempfile.TemporaryDirectory() as d:
        for f in files:
            rel = Path(f["path"]).as_posix().lstrip("/")
            if ".." in Path(rel).parts:
                continue
            p = Path(d) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(f["content"], encoding="utf-8")
        return extract_dir(d, apply_filters=apply_filters, min_newlines=min_newlines)


# ---------------------------------------------------------------------------- model
def file_sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def model_hash(model_dir=DEFAULT_MODEL_DIR):
    """SHA-256 over every file that determines the model's output (weights, adapter config,
    tokenizer, thresholds) -> the value recorded in the ruleset's modelVersionHashes."""
    model_dir = Path(model_dir)
    h = hashlib.sha256()
    cfg = json.load(open(model_dir / "model_b_config.json"))
    h.update(f'{cfg["config"]["model"]}@{BASE_REVISION}'.encode())
    for name in ("adapter_model.safetensors", "adapter_config.json", "model_b_config.json",
                 "tokenizer.json", "tokenizer_config.json"):
        p = model_dir / name
        if p.exists():
            h.update(name.encode()); h.update(file_sha256(p).encode())
    return h.hexdigest()


class ModelB:
    def __init__(self, model_dir=DEFAULT_MODEL_DIR, threads=None):
        import torch
        from peft import PeftModel
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        from transformers.utils import logging as hf_logging
        hf_logging.set_verbosity_error()   # the base model's fresh classifier head is replaced by the adapter's
        self.torch = torch
        self.model_dir = Path(model_dir)
        cfg = json.load(open(self.model_dir / "model_b_config.json"))
        self.cfg = cfg
        self.classes = cfg["classes"]
        self.win, self.stride, self.max_win = cfg["win"], cfg["stride"], cfg["max_eval_windows"]
        if "thresholds_raw" in cfg:          # per-class thresholds (v8 run 6 onwards)
            self.fail, self.review = cfg["thresholds_raw"]["fail"], cfg["thresholds_raw"]["review"]
        else:                                # older run: one threshold shared by every class
            self.fail = {c: cfg["threshold_fail_raw"] for c in self.classes}
            self.review = {c: cfg["threshold_review_raw"] for c in self.classes}
        # MODEL_B_DEVICE=cuda (opt-in, e.g. Kaggle evaluation runs): CPU stays the
        # default; the training notebook's parity check puts CPU vs GPU at <= 1e-4.
        self.device = os.environ.get("MODEL_B_DEVICE", "cpu")
        if self.device.startswith("cuda"):
            os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")  # needed for deterministic CUDA matmuls
        torch.manual_seed(0)
        torch.set_num_threads(threads or int(os.environ.get("MODEL_B_THREADS", min(8, os.cpu_count() or 1))))
        torch.use_deterministic_algorithms(True)
        self.tok = AutoTokenizer.from_pretrained(self.model_dir)
        base = AutoModelForSequenceClassification.from_pretrained(
            cfg["config"]["model"], revision=BASE_REVISION, num_labels=len(self.classes),
            problem_type="multi_label_classification", torch_dtype=torch.float32)
        self.model = PeftModel.from_pretrained(base, self.model_dir).merge_and_unload().eval().to(self.device)
        self.hash = model_hash(self.model_dir)
        self._cache = {}

    # windows: same as WindowDataset(train=False) in train_v8.py
    def _windows(self, text):
        ids = self.tok(text, add_special_tokens=False, truncation=False)["input_ids"]
        if not ids:
            return []
        W = self.win
        starts = [0] if len(ids) <= W else list(range(0, len(ids) - W + 1, self.stride))
        if len(ids) > W and starts[-1] + W < len(ids):
            starts.append(len(ids) - W)
        cand = [(s0, min(s0 + W, len(ids))) for s0 in starts]
        k = self.max_win
        if len(cand) > k:
            cand = [cand[round(i * (len(cand) - 1) / (k - 1))] for i in range(k)]
        return [[self.tok.cls_token_id] + ids[a:b] + [self.tok.sep_token_id] for a, b in cand]

    def raw_scores(self, texts, batch=16):
        """texts (already prepared model_code) -> array [n, K] of raw per-class scores.

        Scores are cached per text (sha256): the model is deterministic, and a
        rescan or a new release of a server repeats most of its functions.
        """
        keys = [hashlib.sha256(t.encode("utf-8")).hexdigest() for t in texts]
        miss = sorted({k: i for i, k in enumerate(keys) if k not in self._cache}.values())
        if miss:
            S = self._raw_scores_uncached([texts[i] for i in miss], batch)
            if len(self._cache) + len(miss) > CACHE_MAX:
                self._cache.clear()
            for i, row in zip(miss, S):
                self._cache[keys[i]] = row
        return np.array([self._cache[k] for k in keys]).reshape(len(texts), len(self.classes))

    def _raw_scores_uncached(self, texts, batch):
        torch = self.torch
        wins, owner = [], []
        for i, t in enumerate(texts):
            for w in self._windows(t):
                wins.append(w); owner.append(i)
        S = np.zeros((len(texts), len(self.classes)))
        by_len = defaultdict(list)
        for j, w in enumerate(wins):
            by_len[len(w)].append(j)
        with torch.inference_mode():
            for L in sorted(by_len):
                idx = by_len[L]
                for b in range(0, len(idx), batch):
                    part = idx[b:b + batch]
                    x = torch.tensor([wins[j] for j in part], device=self.device)
                    logits = self.model(input_ids=x, attention_mask=torch.ones_like(x)).logits.double().cpu().numpy()
                    p = 1 / (1 + np.exp(-logits))
                    for j, row in zip(part, p):
                        S[owner[j]] = np.maximum(S[owner[j]], row)
        return np.round(S, 4)

    def calibrate(self, S):
        """Same piecewise-linear map as train_v8.calibrate()."""
        C = np.zeros_like(S, dtype=np.float64)
        for j, c in enumerate(self.classes):
            x, rv, fl = S[:, j], self.review[c], self.fail[c]
            lo = REVIEW_CAL * x / max(rv, 1e-9)
            if fl is None:
                hi = REVIEW_CAL + (FAIL_CAL - 0.01 - REVIEW_CAL) * (x - rv) / max(1 - rv, 1e-9)
                C[:, j] = np.where(x < rv, lo, hi)
            else:
                mid = REVIEW_CAL + (FAIL_CAL - REVIEW_CAL) * (x - rv) / max(fl - rv, 1e-9)
                top = FAIL_CAL + (1 - FAIL_CAL) * (x - fl) / max(1 - fl, 1e-9)
                C[:, j] = np.where(x < rv, lo, np.where(x < fl, mid, top))
        return np.round(np.clip(C, 0, 1), 4)

    def score_functions(self, funcs):
        """funcs: [{code, language, ...}] -> same dicts with raw/calibrated scores and top class."""
        if not funcs:
            return []
        # identical functions (vendored or bundled copies) are scored once
        uniq = {}
        for f in funcs:
            uniq.setdefault((f["language"], f["code"]), len(uniq))
        rows = [{"id": str(i), "language": lang, "code": code} for (lang, code), i in uniq.items()]
        textprep.prepare(rows)
        U = self.raw_scores([r["model_code"] for r in rows])
        S = U[[uniq[(f["language"], f["code"])] for f in funcs]]
        C = self.calibrate(S)
        out = []
        for i, f in enumerate(funcs):
            j = int(C[i].argmax())
            out.append({**{k: v for k, v in f.items() if k != "code"},
                        "score": float(C[i, j]), "class": self.classes[j],
                        "threat": CLASS_INFO[self.classes[j]][0], "cwe": CLASS_INFO[self.classes[j]][1],
                        "calibrated": dict(zip(self.classes, map(float, C[i]))),
                        "raw": dict(zip(self.classes, map(float, S[i])))})
        return out

    def scan(self, funcs, top_k=10):
        """Repository-level result for the marketplace: score = max over functions."""
        t0 = time.time()
        scored = self.score_functions(funcs)
        scored.sort(key=lambda r: -r["score"])
        top = scored[0] if scored else None
        score = top["score"] if top else 0.0
        verdict = "FAIL" if score >= FAIL_CAL else "REVIEW" if score >= REVIEW_CAL else "PASS"
        flagged = [r for r in scored if r["score"] >= REVIEW_CAL]
        evidence = [f"{r['threat']} ({r['cwe']}) in {r['func_name']} at {r['file']}:{r['start_line']} "
                    f"score {r['score']:.2f}" for r in flagged[:top_k]]
        return {"analyzer": "MODEL_B_CODE", "model_version": MODEL_VERSION, "model_hash": self.hash,
                "score": score, "verdict_hint": verdict, "threat": top["threat"] if top and score >= REVIEW_CAL else "none",
                "n_functions": len(scored), "n_flagged": len(flagged), "evidence": evidence,
                "findings": flagged[:100], "seconds": round(time.time() - t0, 2)}


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("path"); s.add_argument("--json", action="store_true")
    sub.add_parser("hash")
    a = ap.parse_args()
    if a.cmd == "hash":
        print(model_hash()); return
    m = ModelB()
    res = m.scan(extract_dir(a.path))
    if a.json:
        print(json.dumps(res, indent=1)); return
    print(f"{res['verdict_hint']}  score {res['score']:.3f}  ({res['n_functions']} functions, "
          f"{res['n_flagged']} flagged, {res['seconds']} s)")
    for e in res["evidence"]:
        print("  -", e)


if __name__ == "__main__":
    main()
