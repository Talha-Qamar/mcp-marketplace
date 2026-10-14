"""Shared fixture plumbing, used by both ``tests/`` and ``scripts/``.

Keeping the expectation table and the fixture locations in one module means
the unit tests and the metrics report can never disagree about what
"correct" means.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

TESTS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TESTS_DIR.parent
SRC_DIR = PROJECT_ROOT / "src"

FIXTURES_DIR = TESTS_DIR / "fixtures"
VULNERABLE_DIR = FIXTURES_DIR / "vulnerable"
SAFE_DIR = FIXTURES_DIR / "safe"
EDGE_DIR = FIXTURES_DIR / "edge"
EXPECTATIONS_PATH = FIXTURES_DIR / "expectations.json"


def ensure_importable() -> None:
    """Make ``ast_taint`` importable straight from ``src/`` without install."""
    if str(SRC_DIR) not in sys.path:
        sys.path.insert(0, str(SRC_DIR))


def load_expectations() -> Dict[str, Any]:
    with EXPECTATIONS_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def _cases(directory: Path, group: str) -> List[Tuple[str, Path, Dict[str, Any]]]:
    expectations = load_expectations()[group]
    out: List[Tuple[str, Path, Dict[str, Any]]] = []
    for name in sorted(expectations):
        if expectations[name].get("materialized"):
            continue  # written at test time, see materialize_non_utf8
        out.append((name, directory / name, expectations[name]))
    return out


def vulnerable_cases():
    return _cases(VULNERABLE_DIR, "vulnerable")


def safe_cases():
    return _cases(SAFE_DIR, "safe")


def edge_cases():
    return _cases(EDGE_DIR, "edge")


# ---------------------------------------------------------------------------
# Edge fixture 3 is materialized rather than committed.
#
# It deliberately contains a byte (0xFF) that is not valid UTF-8, to exercise
# the decoding fallback in ``read_source``. A file like that does not survive
# a round trip through git autocrlf, most editors, or a GitHub diff view, so
# storing it on disk makes the test quietly stop testing anything. Building it
# from an explicit bytes literal keeps the byte exact, forever.
# ---------------------------------------------------------------------------

NON_UTF8_NAME = "e03_non_utf8.py"

NON_UTF8_SOURCE_BYTES = (
    b'"""Edge 3: a stray non-UTF-8 byte in the source."""\n'
    b"\n"
    b"from mcp.server import tool\n"
    b"\n"
    b'LABEL = "caf\xff"\n'
    b"\n"
    b"\n"
    b"@tool\n"
    b"def label():\n"
    b'    """Return a label."""\n'
    b"    return LABEL\n"
)


def materialize_non_utf8(directory: Path) -> Path:
    """Write the non-UTF-8 edge fixture into ``directory`` and return it."""
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / NON_UTF8_NAME
    target.write_bytes(NON_UTF8_SOURCE_BYTES)
    return target
