"""Command-line entry point.

    python -m ast_taint scan path/to/server.py
    python -m ast_taint scan path/to/repo --json --out results.json
    python -m ast_taint features path/to/repo --out features.jsonl
    python -m ast_taint scan path/to/repo --all-functions

Exit code 0 when no HIGH severity finding was produced, 1 when at least one
was - usable as a CI gate.  2 is reserved for usage/IO errors.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Sequence, TextIO

from .analyzer import analyze_file, analyze_repo
from .features import FEATURE_NAMES, label_hint, to_feature_vector
from .models import FileAnalysis, Severity

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _arrow(stream: TextIO) -> str:
    """Prefer a real arrow, fall back to ASCII on narrow code pages."""
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        "→".encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return "->"
    return "→"


def _collect(path: Path, all_functions: bool) -> List[FileAnalysis]:
    if path.is_dir():
        return analyze_repo(path, all_functions=all_functions)
    return [analyze_file(path, all_functions=all_functions)]


def _has_high(analyses: Sequence[FileAnalysis]) -> bool:
    return any(
        hit.severity is Severity.HIGH
        for analysis in analyses
        for hit in analysis.all_hits
    )


def _write(text: str, out: Optional[str], stream: TextIO) -> None:
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(text, encoding="utf-8")
    else:
        stream.write(text)
        if not text.endswith("\n"):
            stream.write("\n")


def render_human(analyses: Sequence[FileAnalysis], arrow: str = "->") -> str:
    lines: List[str] = []
    n_tools = 0
    counts = {Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 0}
    n_unparseable = 0

    for analysis in analyses:
        lines.append(analysis.file_path)
        if not analysis.parse_ok:
            n_unparseable += 1
            lines.append("    ! parse failed: {}".format(analysis.error))
            lines.append("")
            continue
        if not analysis.tools:
            lines.append("    no tools found")
            lines.append("")
            continue

        for tool in analysis.tools:
            n_tools += 1
            if not tool.parse_ok:
                lines.append(
                    "    ! {}: analysis failed: {}".format(tool.tool_name, tool.error)
                )
                continue
            if not tool.hits:
                lines.append(
                    "    ok   {}  (line {})".format(tool.tool_name, tool.lineno)
                )
                continue
            lines.append(
                "    [{}] {}  (line {})".format(
                    tool.max_severity.value.upper(), tool.tool_name, tool.lineno
                )
            )
            for hit in tool.hits:
                counts[hit.severity] = counts.get(hit.severity, 0) + 1
                where = (
                    "arg {}".format(hit.tainted_arg_index)
                    if hit.tainted_arg_index is not None
                    else "kwarg {}".format(hit.tainted_arg_name)
                )
                lines.append(
                    "        {:<8} {} ({}) at line {}, {}".format(
                        hit.severity.value.upper(),
                        hit.sink_name,
                        hit.category.value,
                        hit.lineno,
                        where,
                    )
                )
                lines.append("            flow: {}".format(hit.render_flow(arrow)))
                lines.append(
                    "            hops: {}   sanitized: {}".format(
                        hit.n_hops, "yes" if hit.sanitized else "no"
                    )
                )
                lines.append(
                    "        {:>5} | {}".format(hit.lineno, hit.code_excerpt)
                )
        lines.append("")

    total = sum(counts.values())
    lines.append(
        "{} file(s), {} tool(s), {} finding(s) "
        "({} high, {} medium, {} low){}".format(
            len(analyses),
            n_tools,
            total,
            counts[Severity.HIGH],
            counts[Severity.MEDIUM],
            counts[Severity.LOW],
            ", {} unparseable".format(n_unparseable) if n_unparseable else "",
        )
    )
    return "\n".join(lines) + "\n"


def render_json(analyses: Sequence[FileAnalysis]) -> str:
    payload = [analysis.to_dict() for analysis in analyses]
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_features(analyses: Sequence[FileAnalysis]) -> str:
    lines: List[str] = []
    for analysis in analyses:
        for tool in analysis.tools:
            if not tool.parse_ok:
                continue
            record = {
                "features": to_feature_vector(tool),
                "file": analysis.file_path,
                "label_hint": label_hint(tool),
                "tool": tool.tool_name,
            }
            lines.append(json.dumps(record, sort_keys=True, ensure_ascii=False))
    return "\n".join(lines) + ("\n" if lines else "")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ast_taint",
        description=(
            "Deterministic static taint analysis for MCP server tool "
            "functions. The analysed code is never executed."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="analyse a file or repository")
    scan.add_argument("path", help="a .py file or a directory")
    scan.add_argument("--json", action="store_true", help="emit the full result tree")
    scan.add_argument("--out", help="write to this file instead of stdout")
    scan.add_argument(
        "--all-functions",
        action="store_true",
        help="analyse every function, not just @tool-decorated ones",
    )

    features = sub.add_parser(
        "features", help="emit Model B feature vectors as JSONL"
    )
    features.add_argument("path", help="a .py file or a directory")
    features.add_argument("--out", help="write to this file instead of stdout")
    features.add_argument(
        "--all-functions",
        action="store_true",
        help="analyse every function, not just @tool-decorated ones",
    )

    names = sub.add_parser(
        "feature-names", help="print the frozen feature vector contract"
    )
    names.add_argument("--out", help="write to this file instead of stdout")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "feature-names":
        _write(json.dumps(list(FEATURE_NAMES), indent=2), args.out, sys.stdout)
        return EXIT_CLEAN

    path = Path(args.path)
    if not path.exists():
        sys.stderr.write("error: no such file or directory: {}\n".format(path))
        return EXIT_ERROR

    analyses = _collect(path, args.all_functions)

    if args.command == "scan":
        text = (
            render_json(analyses)
            if args.json
            else render_human(analyses, _arrow(sys.stdout))
        )
    else:
        text = render_features(analyses)

    _write(text, args.out, sys.stdout)
    return EXIT_FINDINGS if _has_high(analyses) else EXIT_CLEAN


def run() -> None:  # console_scripts entry point
    sys.exit(main())
