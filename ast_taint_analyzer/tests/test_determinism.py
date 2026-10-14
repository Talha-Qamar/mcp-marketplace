"""Determinism is a product property here, not a nicety.

The attestation that MCP Secure signs binds a verdict to a fingerprint. If
the same bytes could produce two different verdicts, the signature would be
meaningless. These tests are the guard on that claim.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys

import pytest

from ast_taint import analyze_file, analyze_source
from ast_taint.features import to_feature_vector
from fixture_support import EDGE_DIR, SAFE_DIR, VULNERABLE_DIR

ALL_FIXTURES = sorted(
    list(VULNERABLE_DIR.glob("*.py"))
    + list(SAFE_DIR.glob("*.py"))
    + list(EDGE_DIR.glob("*.py"))
)

HASH_SEEDS = ["0", "1", "42", "12345", "random"]

#: Runs in a fresh interpreter so a different PYTHONHASHSEED really applies.
DRIVER = (
    "import hashlib, json, sys\n"
    "from ast_taint import analyze_repo\n"
    "payload = [a.to_dict() for a in analyze_repo(sys.argv[1])]\n"
    "blob = json.dumps(payload, sort_keys=True, ensure_ascii=False)\n"
    "sys.stdout.write(hashlib.sha256(blob.encode('utf-8')).hexdigest())\n"
)


def serialize(analysis) -> str:
    return json.dumps(analysis.to_dict(), sort_keys=True, ensure_ascii=False)


@pytest.mark.parametrize("path", ALL_FIXTURES, ids=lambda p: p.name)
def test_fifty_runs_are_byte_identical(path):
    source = path.read_bytes().decode("latin-1")
    first = serialize(analyze_source(source, file_path=path.name))
    for _ in range(50):
        assert serialize(analyze_source(source, file_path=path.name)) == first


@pytest.mark.parametrize("path", ALL_FIXTURES, ids=lambda p: p.name)
def test_feature_vectors_are_stable_across_reanalysis(path):
    first = [to_feature_vector(t) for t in analyze_file(path).tools]
    for _ in range(10):
        assert [to_feature_vector(t) for t in analyze_file(path).tools] == first


def test_results_are_hashable_and_equal():
    source = 'import os\n@tool\ndef run(q):\n    """D."""\n    os.system(q)\n'
    a = analyze_source(source)
    b = analyze_source(source)
    assert a == b
    assert hash(a.tools[0].hits[0]) == hash(b.tools[0].hits[0])


def test_json_keys_are_sorted():
    source = 'import os\n@tool\ndef run(q):\n    """D."""\n    os.system(q)\n'
    payload = analyze_source(source).to_dict()
    assert list(payload) == sorted(payload)
    assert list(payload["tools"][0]) == sorted(payload["tools"][0])
    assert list(payload["tools"][0]["hits"][0]) == sorted(
        payload["tools"][0]["hits"][0]
    )


def test_hits_are_ordered_by_source_position():
    source = (
        "import os\n@tool\ndef run(q):\n"
        '    """D."""\n'
        "    os.system(q)\n"
        "    open(q)\n"
        "    eval(q)\n"
    )
    hits = analyze_source(source).tools[0].hits
    assert [h.lineno for h in hits] == sorted(h.lineno for h in hits)


@pytest.mark.parametrize("seed", HASH_SEEDS)
def test_output_is_independent_of_python_hash_seed(
    seed, subprocess_env, src_dir, project_root
):
    """Catches accidental set/dict ordering leaking into the result.

    Note: no ``-I``/``-E`` here on purpose - isolated mode would discard the
    very ``PYTHONHASHSEED`` this test is varying (and ``PYTHONPATH`` with it).
    """
    env = dict(subprocess_env)
    env["PYTHONHASHSEED"] = seed
    result = subprocess.run(
        [sys.executable, "-c", DRIVER, str(VULNERABLE_DIR)],
        env=env,
        cwd=str(project_root),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert len(result.stdout.strip()) == 64

    reference = [a.to_dict() for a in _in_process(VULNERABLE_DIR)]
    blob = json.dumps(reference, sort_keys=True, ensure_ascii=False)
    expected = hashlib.sha256(blob.encode("utf-8")).hexdigest()
    assert result.stdout.strip() == expected


def _in_process(directory):
    from ast_taint import analyze_repo

    return analyze_repo(directory)
