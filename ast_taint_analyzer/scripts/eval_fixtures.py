"""Run the analyzer over every fixture and print a confusion matrix.

    python scripts/eval_fixtures.py

Target is 100%. These fixtures are our own unit tests, not a held-out
benchmark - anything less than perfect here is a bug in the engine, never a
"model limitation". The real evaluation happens against the held-out corpus
in Part 1, with Model C auditing the labels.

Exit code 0 when everything matches, 1 otherwise.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

from ast_taint import analyze_file  # noqa: E402
from fixture_support import (  # noqa: E402
    EDGE_DIR,
    SAFE_DIR,
    VULNERABLE_DIR,
    load_expectations,
    materialize_non_utf8,
)

Mismatch = Tuple[str, str]


def _check_vulnerable(expectations) -> Tuple[int, int, List[Mismatch]]:
    """Returns (true_positives, false_negatives, detail_mismatches)."""
    true_positives = 0
    false_negatives = 0
    mismatches: List[Mismatch] = []

    for name in sorted(expectations):
        expected = expectations[name]
        analysis = analyze_file(VULNERABLE_DIR / name)
        if not analysis.parse_ok or not analysis.tools:
            false_negatives += 1
            mismatches.append((name, "file did not analyse: {}".format(analysis.error)))
            continue

        tool = analysis.tools[0]
        if not tool.reaches_sink:
            false_negatives += 1
            mismatches.append((name, "expected a finding, got none"))
            continue
        true_positives += 1

        if tool.max_severity.value != expected["severity"]:
            mismatches.append(
                (
                    name,
                    "severity {} != expected {}".format(
                        tool.max_severity.value, expected["severity"]
                    ),
                )
            )
        if tool.n_hops_min != expected["min_hops"]:
            mismatches.append(
                (
                    name,
                    "min_hops {} != expected {}".format(
                        tool.n_hops_min, expected["min_hops"]
                    ),
                )
            )
        categories = [c.value for c in tool.sink_categories]
        if categories != expected["categories"]:
            mismatches.append(
                (name, "categories {} != expected {}".format(categories, expected["categories"]))
            )
        if tool.hits[0].sanitized is not expected["sanitized"]:
            mismatches.append((name, "sanitized flag mismatch"))

    return true_positives, false_negatives, mismatches


def _check_safe(expectations) -> Tuple[int, int, List[Mismatch]]:
    """Returns (true_negatives, false_positives, detail_mismatches)."""
    true_negatives = 0
    false_positives = 0
    mismatches: List[Mismatch] = []

    for name in sorted(expectations):
        analysis = analyze_file(SAFE_DIR / name)
        flagged = [t for t in analysis.tools if t.reaches_sink]
        if flagged:
            false_positives += 1
            for tool in flagged:
                for hit in tool.hits:
                    mismatches.append(
                        (
                            name,
                            "FALSE POSITIVE {} at line {} via {}".format(
                                hit.sink_name, hit.lineno, hit.render_flow()
                            ),
                        )
                    )
        else:
            true_negatives += 1

    return true_negatives, false_positives, mismatches


def _check_edge(expectations) -> Tuple[int, List[Mismatch]]:
    handled = 0
    mismatches: List[Mismatch] = []

    with tempfile.TemporaryDirectory() as tmp:
        for name in sorted(expectations):
            expected = expectations[name]
            if expected.get("materialized"):
                path = materialize_non_utf8(Path(tmp))
            else:
                path = EDGE_DIR / name
            try:
                analysis = analyze_file(path)
            except Exception as exc:  # the whole point: this must never happen
                mismatches.append((name, "RAISED {}: {}".format(type(exc).__name__, exc)))
                continue

            handled += 1
            if analysis.parse_ok is not expected["parse_ok"]:
                mismatches.append(
                    (
                        name,
                        "parse_ok {} != expected {}".format(
                            analysis.parse_ok, expected["parse_ok"]
                        ),
                    )
                )
            if len(analysis.tools) != expected["n_tools"]:
                mismatches.append(
                    (
                        name,
                        "n_tools {} != expected {}".format(
                            len(analysis.tools), expected["n_tools"]
                        ),
                    )
                )

    return handled, mismatches


def main() -> int:
    expectations = load_expectations()

    tp, fn, vuln_detail = _check_vulnerable(expectations["vulnerable"])
    tn, fp, safe_detail = _check_safe(expectations["safe"])
    handled, edge_detail = _check_edge(expectations["edge"])

    n_vuln = len(expectations["vulnerable"])
    n_safe = len(expectations["safe"])
    n_edge = len(expectations["edge"])

    print("AST Taint Analyzer - fixture evaluation")
    print("=" * 56)
    print()
    print("Confusion matrix (flagged vs expected)")
    print()
    print("                      predicted FLAG   predicted CLEAN")
    print("  expected FLAG  {:>12}   {:>15}".format(tp, fn))
    print("  expected CLEAN {:>12}   {:>15}".format(fp, tn))
    print()

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / (n_vuln + n_safe) if (n_vuln + n_safe) else 0.0

    print("  precision {:.3f}   recall {:.3f}   f1 {:.3f}   accuracy {:.3f}".format(
        precision, recall, f1, accuracy
    ))
    print()
    print("  vulnerable fixtures : {}/{} detected".format(tp, n_vuln))
    print("  safe fixtures       : {}/{} clean".format(tn, n_safe))
    print("  edge fixtures       : {}/{} handled without an exception".format(
        handled, n_edge
    ))
    print()

    severity_detail = [m for m in vuln_detail if "severity" in m[1] or "min_hops" in m[1]
                       or "categories" in m[1] or "sanitized" in m[1]]
    print("  detail mismatches   : {}".format(len(severity_detail)))
    print()

    all_detail = vuln_detail + safe_detail + edge_detail
    if all_detail:
        print("Mismatches")
        print("-" * 56)
        for name, message in all_detail:
            print("  {:<36} {}".format(name, message))
        print()
        print("RESULT: FAIL ({} mismatch(es))".format(len(all_detail)))
        return 1

    print("RESULT: PASS (100% on all {} fixtures)".format(n_vuln + n_safe + n_edge))
    return 0


if __name__ == "__main__":
    sys.exit(main())
