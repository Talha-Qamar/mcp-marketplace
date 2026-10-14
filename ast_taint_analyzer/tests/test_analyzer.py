"""The fixture suite plus targeted unit tests for the taint engine."""

from __future__ import annotations

import pytest

from ast_taint import analyze_file, analyze_repo, analyze_source
from ast_taint.models import Severity, SinkCategory
from fixture_support import edge_cases, safe_cases, vulnerable_cases


def one_tool(source):
    analysis = analyze_source(source)
    assert analysis.parse_ok
    assert len(analysis.tools) == 1
    return analysis.tools[0]


def wrap(body, params="q", decorator="@tool", header="import os\n"):
    indented = "\n".join("    " + line for line in body.strip().splitlines())
    return "{}{}\ndef run({}):\n    \"\"\"Doc.\"\"\"\n{}\n".format(
        header, decorator, params, indented
    )


# ---------------------------------------------------------------------------
# 8.1 - must-flag fixtures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,path,expected",
    vulnerable_cases(),
    ids=[case[0] for case in vulnerable_cases()],
)
def test_vulnerable_fixture(name, path, expected):
    analysis = analyze_file(path)
    assert analysis.parse_ok, analysis.error
    assert len(analysis.tools) == 1
    tool = analysis.tools[0]

    assert tool.tool_name == expected["tool"]
    assert list(tool.params) == expected["params"]
    assert tool.reaches_sink is True
    assert tool.max_severity.value == expected["severity"]
    assert tool.n_hops_min == expected["min_hops"]
    assert len(tool.hits) == expected["n_hits"]
    assert [c.value for c in tool.sink_categories] == expected["categories"]

    hit = tool.hits[0]
    assert hit.sanitized is expected["sanitized"]
    assert hit.source_param == expected["source_param"]
    assert hit.n_hops == expected["min_hops"]
    assert hit.code_excerpt, "every finding needs a reconstructable excerpt"
    assert hit.lineno >= 1

    if "path" in expected:
        assert list(hit.path) == expected["path"]
    if "sink_name" in expected:
        assert hit.sink_name == expected["sink_name"]
    if "has_fstring_flow" in expected:
        assert tool.flow_facts.has_fstring_flow is expected["has_fstring_flow"]
    if "shell_true_present" in expected:
        assert tool.flow_facts.shell_true_present is expected["shell_true_present"]


# ---------------------------------------------------------------------------
# 8.2 - must-NOT-flag fixtures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,path,expected",
    safe_cases(),
    ids=[case[0] for case in safe_cases()],
)
def test_safe_fixture(name, path, expected):
    analysis = analyze_file(path)
    assert analysis.parse_ok, analysis.error
    assert len(analysis.tools) == expected["n_tools"]
    for tool in analysis.tools:
        assert tool.hits == (), "false positive in {}: {}".format(name, tool.hits)
        assert tool.reaches_sink is False
        assert tool.max_severity is Severity.NONE
        assert tool.n_hops_min is None
        assert tool.sink_categories == ()


def test_undecorated_file_is_flagged_under_all_functions(safe_dir):
    """Safe fixture 9 is only safe because it declares no tools."""
    path = safe_dir / "s09_no_tool_decorators.py"
    assert analyze_file(path).tools == ()

    analysis = analyze_file(path, all_functions=True)
    assert len(analysis.tools) == 1
    assert analysis.tools[0].max_severity is Severity.HIGH


# ---------------------------------------------------------------------------
# 8.3 - edge fixtures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,path,expected",
    edge_cases(),
    ids=[case[0] for case in edge_cases()],
)
def test_edge_fixture(name, path, expected):
    analysis = analyze_file(path)
    assert analysis.parse_ok is expected["parse_ok"]
    assert len(analysis.tools) == expected["n_tools"]
    if not expected["parse_ok"]:
        assert analysis.error, "a parse failure must carry a structured error"
        assert analysis.content_sha256, "the fingerprint survives a parse failure"
    if expected.get("flagged"):
        assert any(tool.hits for tool in analysis.tools)


def test_non_utf8_file_is_decoded_and_analysed(non_utf8_file):
    analysis = analyze_file(non_utf8_file)
    assert analysis.parse_ok, analysis.error
    assert [t.tool_name for t in analysis.tools] == ["label"]
    assert analysis.tools[0].hits == ()


def test_depth_guard_survives_a_pathological_expression():
    expr = "q" + ' + "x"' * 300  # 3x the MAX_EXPR_DEPTH guard
    source = 'import os\n@tool\ndef run(q):\n    """D."""\n    os.system({})\n'.format(
        expr
    )
    analysis = analyze_source(source)
    assert analysis.parse_ok
    assert len(analysis.tools) == 1
    assert analysis.tools[0].parse_ok


def test_missing_file_returns_structured_error(tmp_path):
    analysis = analyze_file(tmp_path / "nope.py")
    assert analysis.parse_ok is False
    assert analysis.error


# ---------------------------------------------------------------------------
# Alias resolution
# ---------------------------------------------------------------------------


def test_import_as_alias():
    tool = one_tool(wrap("o.system(q)", header="import os as o\n"))
    assert tool.hits[0].sink_name == "os.system"


def test_from_import_alias():
    tool = one_tool(wrap("system(q)", header="from os import system\n"))
    assert tool.hits[0].sink_name == "os.system"


def test_from_import_with_rename():
    tool = one_tool(wrap("shell(q)", header="from os import system as shell\n"))
    assert tool.hits[0].sink_name == "os.system"


def test_submodule_import_alias():
    tool = one_tool(
        wrap("sp.run(q, shell=True)", header="import subprocess as sp\n")
    )
    assert tool.hits[0].sink_name == "subprocess.run"


def test_function_local_import_still_resolves():
    source = (
        "@tool\n"
        "def run(q):\n"
        '    """D."""\n'
        "    import os as o\n"
        "    o.system(q)\n"
    )
    tool = one_tool(source)
    assert tool.hits[0].sink_name == "os.system"


# ---------------------------------------------------------------------------
# Conditional sinks
# ---------------------------------------------------------------------------


def test_subprocess_without_shell_is_not_a_sink():
    assert one_tool(wrap('subprocess.run(["ls", q])', header="import subprocess\n")).hits == ()


def test_subprocess_shell_false_is_not_a_sink():
    assert one_tool(
        wrap("subprocess.run(q, shell=False)", header="import subprocess\n")
    ).hits == ()


def test_subprocess_shell_true_is_a_sink():
    tool = one_tool(wrap("subprocess.run(q, shell=True)", header="import subprocess\n"))
    assert tool.max_severity is Severity.HIGH
    assert tool.flow_facts.shell_true_present is True


def test_shell_bound_to_a_true_variable_is_resolved():
    tool = one_tool(
        wrap(
            "use_shell = True\nsubprocess.run(q, shell=use_shell)",
            header="import subprocess\n",
        )
    )
    assert tool.max_severity is Severity.HIGH


def test_shell_bound_to_a_false_variable_is_resolved():
    tool = one_tool(
        wrap(
            "use_shell = False\nsubprocess.run(q, shell=use_shell)",
            header="import subprocess\n",
        )
    )
    assert tool.hits == ()


def test_unknown_shell_expression_is_treated_conservatively():
    tool = one_tool(
        wrap("subprocess.run(q, shell=flag())", header="import subprocess\n")
    )
    assert tool.reaches_sink is True


def test_yaml_safe_loader_variants_are_clean():
    for loader in ("yaml.SafeLoader", "yaml.CSafeLoader"):
        tool = one_tool(
            wrap("yaml.load(q, Loader={})".format(loader), header="import yaml\n")
        )
        assert tool.hits == (), loader


def test_yaml_unsafe_loader_is_flagged():
    tool = one_tool(wrap("yaml.load(q, Loader=yaml.Loader)", header="import yaml\n"))
    assert tool.max_severity is Severity.MEDIUM


def test_yaml_positional_safe_loader_is_clean():
    tool = one_tool(wrap("yaml.load(q, yaml.SafeLoader)", header="import yaml\n"))
    assert tool.hits == ()


# ---------------------------------------------------------------------------
# Propagation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        'os.system("ls " + q)',
        'os.system(f"ls {q}")',
        'os.system("ls {}".format(q))',
        'os.system("ls %s" % q)',
        'os.system(" ".join(["ls", q]))',
        "os.system(str(q))",
        "os.system(q.strip())",
        'os.system("ls " + q.upper())',
        "os.system(base64.b64decode(q))",
        "os.system(os.path.join('/tmp', q))",
    ],
)
def test_taint_propagates_through_string_plumbing(body):
    source = "import os\nimport base64\n@tool\ndef run(q):\n    \"\"\"D.\"\"\"\n    " + body + "\n"
    assert one_tool(source).reaches_sink is True


def test_augmented_assignment_propagates():
    tool = one_tool(wrap('cmd = "ls "\ncmd += q\nos.system(cmd)'))
    assert tool.reaches_sink is True


def test_tuple_unpacking_is_conservative():
    tool = one_tool(wrap("a, b = q, q\nos.system(a)"))
    assert tool.reaches_sink is True


def test_walrus_binds_taint():
    tool = one_tool(wrap("if (cmd := q):\n    os.system(cmd)"))
    assert tool.reaches_sink is True


def test_container_mutation_taints_the_container():
    tool = one_tool(wrap('parts = []\nparts.append(q)\nos.system(" ".join(parts))'))
    assert tool.reaches_sink is True


def test_while_loop_reaches_fixpoint():
    tool = one_tool(
        wrap(
            "acc = \"\"\nwhile q:\n    acc = acc + q\nos.system(acc)",
        )
    )
    assert tool.reaches_sink is True


def test_nested_function_inherits_outer_taint():
    tool = one_tool(wrap("def inner():\n    os.system(q)\ninner()"))
    assert tool.reaches_sink is True


def test_nested_function_parameter_shadows_outer_taint():
    tool = one_tool(wrap('def inner(q):\n    os.system("x")\ninner("safe")'))
    assert tool.hits == ()


def test_try_except_merges_conservatively():
    tool = one_tool(
        wrap("try:\n    cmd = q\nexcept ValueError:\n    cmd = 'safe'\nos.system(cmd)")
    )
    assert tool.reaches_sink is True


def test_environment_variable_is_a_secondary_source():
    tool = one_tool(
        wrap('cmd = os.environ["CMD"]\nos.system(cmd)', params="unused")
    )
    assert tool.reaches_sink is True
    assert tool.hits[0].source_param == "<untrusted>"


def test_input_is_a_secondary_source():
    tool = one_tool(wrap("cmd = input()\nos.system(cmd)", params="unused"))
    assert tool.hits[0].source_param == "<untrusted>"


def test_sink_inside_a_return_expression_is_found():
    tool = one_tool(wrap("return eval(q)", header=""))
    assert tool.max_severity is Severity.HIGH


def test_comprehension_iterable_taints_the_result():
    tool = one_tool(wrap('cmds = [c for c in q]\nos.system(" ".join(cmds))'))
    assert tool.reaches_sink is True


# ---------------------------------------------------------------------------
# Untainting - the false-positive guard
# ---------------------------------------------------------------------------


def test_reassignment_to_a_constant_clears_taint():
    assert one_tool(wrap('cmd = q\ncmd = "safe"\nos.system(cmd)')).hits == ()


def test_reassignment_to_an_untainted_expression_clears_taint():
    assert one_tool(wrap('cmd = q\ncmd = "a" + "b"\nos.system(cmd)')).hits == ()


def test_del_clears_taint():
    tool = one_tool(wrap('cmd = q\ndel cmd\ncmd = "safe"\nos.system(cmd)'))
    assert tool.hits == ()


def test_subscript_index_does_not_taint_the_result():
    tool = one_tool(wrap('TABLE = {"a": "ls"}\nos.system(TABLE[q])'))
    assert tool.hits == ()


def test_comparison_result_is_not_tainted():
    tool = one_tool(wrap('flag = q == "x"\nos.system(str(flag))'))
    assert tool.hits == ()


def test_unknown_helper_call_does_not_propagate():
    tool = one_tool(wrap("cmd = helper(q)\nos.system(cmd)"))
    assert tool.hits == ()


# ---------------------------------------------------------------------------
# Severity table
# ---------------------------------------------------------------------------


def test_shell_sink_within_two_hops_is_high():
    assert one_tool(wrap("os.system(q)")).max_severity is Severity.HIGH


def test_shell_sink_beyond_two_hops_is_medium():
    tool = one_tool(wrap("a = q\nb = a\nc = b\nos.system(c)"))
    assert tool.max_severity is Severity.MEDIUM
    assert tool.n_hops_min == 4


def test_file_sink_is_medium_even_at_one_hop():
    tool = one_tool(wrap("open(q)", header=""))
    assert tool.max_severity is Severity.MEDIUM


@pytest.mark.parametrize(
    "sanitizer", ["shlex.quote", "re.escape", "html.escape", "os.path.basename"]
)
def test_sanitized_flow_is_low_but_still_reported(sanitizer):
    module = sanitizer.split(".")[0]
    tool = one_tool(
        wrap(
            "os.system({}(q))".format(sanitizer),
            header="import os\nimport {}\nimport shlex\nimport re\nimport html\n".format(
                module
            ),
        )
    )
    assert tool.max_severity is Severity.LOW
    assert tool.hits[0].sanitized is True


def test_severity_is_the_max_across_hits():
    tool = one_tool(wrap("os.system(q)\nopen(q)"))
    assert tool.max_severity is Severity.HIGH
    assert set(tool.sink_categories) == {SinkCategory.SHELL, SinkCategory.FILE}


# ---------------------------------------------------------------------------
# Repository walking
# ---------------------------------------------------------------------------


def test_analyze_repo_is_sorted_and_relative(vulnerable_dir):
    results = analyze_repo(vulnerable_dir)
    paths = [r.file_path for r in results]
    assert paths == sorted(p.name for p in vulnerable_dir.glob("*.py"))
    assert len(results) == 20


def test_analyze_repo_skips_noise_directories(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "server.py").write_text(
        "import os\n@tool\ndef run(q):\n    os.system(q)\n", encoding="utf-8"
    )
    for skipped in ("venv", ".git", "__pycache__", "site-packages", "tests"):
        (tmp_path / skipped).mkdir()
        (tmp_path / skipped / "noise.py").write_text("x = 1\n", encoding="utf-8")

    results = analyze_repo(tmp_path)
    assert [r.file_path for r in results] == ["pkg/server.py"]


def test_analyze_repo_accepts_a_single_file(vulnerable_dir):
    results = analyze_repo(vulnerable_dir / "v01_direct_concat.py")
    assert len(results) == 1


def test_fingerprint_is_sha256_of_the_source():
    import hashlib

    source = "x = 1\n"
    expected = hashlib.sha256(source.encode("utf-8")).hexdigest()
    assert analyze_source(source).content_sha256 == expected
