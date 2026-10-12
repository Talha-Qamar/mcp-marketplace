"""pytest configuration.

Puts ``src/`` on ``sys.path`` so the suite runs against the working tree
with no install step (``pip install -e .`` also works and is preferred for
real use).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest  # noqa: E402

from fixture_support import (  # noqa: E402
    EDGE_DIR,
    FIXTURES_DIR,
    NON_UTF8_NAME,
    PROJECT_ROOT,
    SAFE_DIR,
    SRC_DIR,
    VULNERABLE_DIR,
    ensure_importable,
    load_expectations,
    materialize_non_utf8,
)

ensure_importable()


@pytest.fixture(scope="session")
def src_dir() -> Path:
    return SRC_DIR


@pytest.fixture(scope="session")
def project_root() -> Path:
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture(scope="session")
def vulnerable_dir() -> Path:
    return VULNERABLE_DIR


@pytest.fixture(scope="session")
def safe_dir() -> Path:
    return SAFE_DIR


@pytest.fixture(scope="session")
def edge_dir() -> Path:
    return EDGE_DIR


@pytest.fixture(scope="session")
def expectations():
    return load_expectations()


@pytest.fixture()
def non_utf8_file(tmp_path: Path) -> Path:
    """The 0xFF-containing edge fixture, written fresh for each test."""
    return materialize_non_utf8(tmp_path)


@pytest.fixture(scope="session")
def subprocess_env():
    """Environment for CLI subprocesses: ``src/`` importable, no bytecode."""
    import os

    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC_DIR)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env
