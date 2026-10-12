"""The frozen Part 2 -> Part 3 contract.

If any of these fail after Model B has been trained, Model B must be
retrained - its weights are indexed by position in this vector.
"""

from __future__ import annotations

import pytest

from ast_taint import analyze_file, analyze_source
from ast_taint.features import (
    FEATURE_CAPS,
    FEATURE_NAMES,
    label_hint,
    to_feature_dict,
    to_feature_vector,
)
from fixture_support import EDGE_DIR, SAFE_DIR, VULNERABLE_DIR

ALL_FIXTURES = sorted(
    list(VULNERABLE_DIR.glob("*.py"))
    + list(SAFE_DIR.glob("*.py"))
    + list(EDGE_DIR.glob("*.py"))
)

#: The frozen order, written out literally so a reordering shows up as a diff
#: in this file and not only as a mysterious accuracy drop in Model B.
EXPECTED_ORDER = [
    "reaches_sink",
    "n_hits",
    "min_hops",
    "max_severity",
    "has_shell_sink",
    "has_exec_sink",
    "has_dynamic_sink",
    "has_file_sink",
    "has_deserialize_sink",
    "any_sanitized",
    "all_sanitized",
    "n_params",
    "n_tainted_vars",
    "has_fstring_flow",
    "has_concat_flow",
    "shell_true_present",
]


def test_feature_names_are_frozen():
    assert list(FEATURE_NAMES) == EXPECTED_ORDER


def test_feature_names_are_unique():
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)


@pytest.mark.parametrize("path", ALL_FIXTURES, ids=lambda p: p.name)
def test_vector_length_and_type_for_every_fixture(path):
    analysis = analyze_file(path)
    for tool in analysis.tools:
        vector = to_feature_vector(tool)
        assert len(vector) == len(FEATURE_NAMES)
        assert all(isinstance(value, float) for value in vector)


@pytest.mark.parametrize("path", ALL_FIXTURES, ids=lambda p: p.name)
def test_vector_and_dict_agree(path):
    analysis = analyze_file(path)
    for tool in analysis.tools:
        as_dict = to_feature_dict(tool)
        assert list(as_dict) == list(FEATURE_NAMES)
        assert list(as_dict.values()) == to_feature_vector(tool)


@pytest.mark.parametrize("path", ALL_FIXTURES, ids=lambda p: p.name)
def test_vector_is_stable_across_calls(path):
    analysis = analyze_file(path)
    for tool in analysis.tools:
        first = to_feature_vector(tool)
        for _ in range(20):
            assert to_feature_vector(tool) == first


def test_clean_tool_vector_is_all_structural_zeros():
    tool = analyze_source(
        '@tool\ndef run(a, b):\n    """D."""\n    return a\n'
    ).tools[0]
    features = to_feature_dict(tool)
    assert features["reaches_sink"] == 0.0
    assert features["n_hits"] == 0.0
    assert features["min_hops"] == 0.0
    assert features["max_severity"] == 0.0
    assert features["any_sanitized"] == 0.0
    assert features["all_sanitized"] == 0.0
    assert features["n_params"] == 2.0


def test_shell_injection_vector():
    source = 'import os\n@tool\ndef run(q):\n    """D."""\n    os.system("ls " + q)\n'
    features = to_feature_dict(analyze_source(source).tools[0])
    assert features["reaches_sink"] == 1.0
    assert features["n_hits"] == 1.0
    assert features["min_hops"] == 1.0
    assert features["max_severity"] == 3.0
    assert features["has_shell_sink"] == 1.0
    assert features["has_exec_sink"] == 0.0
    assert features["has_concat_flow"] == 1.0
    assert features["has_fstring_flow"] == 0.0
    assert features["shell_true_present"] == 0.0


def test_fstring_flow_flag():
    source = 'import os\n@tool\ndef run(q):\n    """D."""\n    os.system(f"ls {q}")\n'
    features = to_feature_dict(analyze_source(source).tools[0])
    assert features["has_fstring_flow"] == 1.0
    assert features["has_concat_flow"] == 0.0


def test_shell_true_present_is_independent_of_taint():
    source = (
        "import subprocess\n"
        "@tool\n"
        "def run(q):\n"
        '    """D."""\n'
        '    subprocess.run("ls", shell=True)\n'
    )
    features = to_feature_dict(analyze_source(source).tools[0])
    assert features["shell_true_present"] == 1.0
    assert features["reaches_sink"] == 0.0


def test_sanitized_flags():
    source = (
        "import os\nimport shlex\n@tool\ndef run(q):\n"
        '    """D."""\n    os.system(shlex.quote(q))\n'
    )
    features = to_feature_dict(analyze_source(source).tools[0])
    assert features["any_sanitized"] == 1.0
    assert features["all_sanitized"] == 1.0
    assert features["max_severity"] == 1.0


def test_any_sanitized_without_all_sanitized():
    source = (
        "import os\nimport shlex\n@tool\ndef run(q):\n"
        '    """D."""\n    os.system(shlex.quote(q))\n    os.system(q)\n'
    )
    features = to_feature_dict(analyze_source(source).tools[0])
    assert features["any_sanitized"] == 1.0
    assert features["all_sanitized"] == 0.0


def test_counts_are_capped():
    params = ", ".join("p{}".format(i) for i in range(25))
    body = "\n".join('    os.system("x" + p{})'.format(i) for i in range(25))
    source = 'import os\n@tool\ndef run({}):\n    """D."""\n{}\n'.format(params, body)
    features = to_feature_dict(analyze_source(source).tools[0])
    assert features["n_params"] == float(FEATURE_CAPS["n_params"])
    assert features["n_hits"] == float(FEATURE_CAPS["n_hits"])
    assert features["n_tainted_vars"] <= float(FEATURE_CAPS["n_tainted_vars"])


def test_min_hops_is_capped():
    chain = "\n".join(
        "    v{} = v{} + 'x'".format(i, i - 1) if i else "    v0 = q + 'x'"
        for i in range(20)
    )
    source = 'import os\n@tool\ndef run(q):\n    """D."""\n{}\n    os.system(v19)\n'.format(
        chain
    )
    features = to_feature_dict(analyze_source(source).tools[0])
    assert features["min_hops"] == float(FEATURE_CAPS["min_hops"])


def test_label_hint_is_derived_from_reaches_sink():
    vulnerable = analyze_source(
        'import os\n@tool\ndef run(q):\n    """D."""\n    os.system(q)\n'
    ).tools[0]
    benign = analyze_source('@tool\ndef run(q):\n    """D."""\n    return q\n').tools[0]
    assert label_hint(vulnerable) == "injection"
    assert label_hint(benign) == "benign"
