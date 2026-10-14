#!/usr/bin/env python3
"""AST taint analyzer as an MCP Secure contract service (spec section 6.4).

    python ast_taint_analyzer/service.py [--port 8701]

Wraps the Part 2 engine unchanged. It analyses the Python tool handlers that
ingestion discovered (tool parameters are the taint sources), and analyses every
function of files without decorated tools (helpers, low-level SDK handlers). Each sink hit
becomes one contract finding, mapped onto the shared threat taxonomy.
"""

import argparse
import ast
import hashlib
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "src"))
sys.path.insert(0, str(HERE.parent / "services" / "analyzer_kit"))

import ast_taint  # noqa: E402
from ast_taint import analyze_source  # noqa: E402
import analyzer_kit as kit  # noqa: E402

ANALYZER_ID = "ast_taint"
CONFIG_PY = HERE / "src" / "ast_taint" / "config.py"

# AST sink category -> shared threat taxonomy (contracts/threats.json)
CATEGORY_THREAT = {
    "shell": ("command_injection", "CWE-78"),
    "exec": ("code_injection", "CWE-94"),
    "dynamic": ("code_injection", "CWE-94"),
    "file": ("path_traversal", "CWE-22"),
    "deserialize": ("unsafe_deserialization", "CWE-502"),
}
# Same table as ruleset astSeverityScores (policy-v2+): high trips the hard-fail gate.
SEVERITY_SCORE = {"high": 1.0, "medium": 0.55, "low": 0.25}


def artifact_hash():
    return "sha256:" + hashlib.sha256(CONFIG_PY.read_bytes()).hexdigest()


ARTIFACT_HASH = artifact_hash()


def identity():
    return {"id": ANALYZER_ID, "version": ast_taint.__version__, "artifact_hash": ARTIFACT_HASH, "engine": "static"}


def health():
    return {
        **identity(),
        "display_name": "AST taint analyzer",
        "description": "Deterministic Python taint analysis: does tool input reach a dangerous sink?",
        "consumes": ["files", "tools"],
        "languages": ["python"],
        "threats": sorted({t for t, _ in CATEGORY_THREAT.values()}),
        "contract_version": kit.CONTRACT_VERSION,
    }


def function_spans(source):
    """(def lineno) -> (start incl. decorators, end) for every function in the file."""
    spans = {}
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return spans
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = min([d.lineno for d in node.decorator_list] + [node.lineno])
            spans[node.lineno] = (start, node.end_lineno)
    return spans


def analyze(bundle, context):
    py_files = [f for f in bundle.get("files", []) if f.get("language") == "python"]
    if not py_files:
        return kit.result(identity(), "not_applicable", notes=["no Python source in bundle"])

    tool_files = {t["file"] for t in bundle.get("tools", []) if t.get("language") == "python"}
    findings, notes = [], []
    analyzed = 0
    for f in py_files:
        decorated = analyze_source(f["content"], f["path"], all_functions=False)
        if not decorated.parse_ok:
            notes.append("parse failed: %s (%s)" % (f["path"], decorated.error))
            continue
        analyzed += 1
        analysis = decorated
        # No decorated tools in this file: analyse every function. That covers
        # low-level SDK and mcp.tool()(fn) handlers, and helper modules that tool
        # handlers call into (the engine is intra-file, so a tool's argument
        # reaching subprocess in a helper file is only seen this way).
        if not decorated.tools:
            analysis = analyze_source(f["content"], f["path"], all_functions=True)
            reason = "tool file without decorators" if f["path"] in tool_files else "helper file"
            notes.append("%s: %s, analysed all functions" % (f["path"], reason))
        spans = function_spans(f["content"])
        for tool in analysis.tools:
            start, end = spans.get(tool.lineno, (tool.lineno, tool.lineno))
            tool_id = kit.tool_for_span(bundle, f["path"], start, end)
            for hit in tool.hits:
                threat, cwe = CATEGORY_THREAT[hit.category.value]
                severity = hit.severity.value
                # Outside a discovered tool handler every parameter is treated as a
                # source, so the flow is possible but not proven to start at tool
                # input: never "high" (the policy's hard-fail), at most "medium".
                unproven = tool_id is None
                if unproven and severity == "high":
                    severity = "medium"
                findings.append({
                    "finding_id": kit.finding_id(ANALYZER_ID, f["path"], hit.lineno, hit.col_offset, hit.sink_name,
                                                 hit.tainted_arg_index, hit.tainted_arg_name or "", threat),
                    "threat": threat,
                    "cwe": cwe,
                    "score": SEVERITY_SCORE.get(severity, 0.0),
                    "severity": severity,
                    "location": {
                        "file": f["path"],
                        "line": hit.lineno,
                        "function": {"name": tool.tool_name, "start_line": start, "end_line": end},
                        "tool_id": tool_id,
                    },
                    "summary": "tainted '%s' reaches %s() in %d hop(s)%s" % (
                        hit.source_param, hit.sink_name, hit.n_hops, ", sanitized" if hit.sanitized else ""),
                    "details": {
                        "category": hit.category.value,
                        "sink": hit.sink_name,
                        "source_param": hit.source_param,
                        "path": list(hit.path),
                        "n_hops": hit.n_hops,
                        "sanitized": hit.sanitized,
                        "code_excerpt": hit.code_excerpt,
                        "engine_severity": hit.severity.value,
                        "source_is_tool_input": not unproven,
                    },
                })
    status = "ok" if analyzed == len(py_files) else ("partial" if analyzed else "error")
    return kit.result(identity(), status, findings, units_total=len(py_files), units_analyzed=analyzed,
                      languages=["python"], notes=notes,
                      error=None if analyzed else "no Python file could be parsed")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=int(os.environ.get("AST_TAINT_PORT", 8701)))
    a = ap.parse_args()
    kit.serve(health, analyze, a.port, a.host, name="ast-taint")


if __name__ == "__main__":
    main()
