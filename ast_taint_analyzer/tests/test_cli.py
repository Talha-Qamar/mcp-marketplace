"""All four documented invocations, plus the exit-code contract."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from ast_taint.cli import main
from ast_taint.features import FEATURE_NAMES
from fixture_support import SAFE_DIR, VULNERABLE_DIR

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def run_module(args, env, cwd):
    return subprocess.run(
        [sys.executable, "-m", "ast_taint"] + args,
        env=env,
        cwd=str(cwd),
        capture_output=True,
        text=True,
    )


# ---------------------------------------------------------------------------
# python -m ast_taint, end to end
# ---------------------------------------------------------------------------


def test_module_entry_point_scans_a_file(subprocess_env, project_root):
    result = run_module(
        ["scan", str(VULNERABLE_DIR / "v01_direct_concat.py")],
        subprocess_env,
        project_root,
    )
    assert result.returncode == EXIT_FINDINGS, result.stderr
    assert "list_directory" in result.stdout
    assert "os.system" in result.stdout
    assert "HIGH" in result.stdout


def test_module_entry_point_json_to_file(subprocess_env, project_root, tmp_path):
    out = tmp_path / "results.json"
    result = run_module(
        ["scan", str(VULNERABLE_DIR), "--json", "--out", str(out)],
        subprocess_env,
        project_root,
    )
    assert result.returncode == EXIT_FINDINGS, result.stderr
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert len(payload) == 20
    assert all(entry["parse_ok"] for entry in payload)


def test_module_entry_point_features_jsonl(subprocess_env, project_root, tmp_path):
    out = tmp_path / "features.jsonl"
    result = run_module(
        ["features", str(VULNERABLE_DIR), "--out", str(out)],
        subprocess_env,
        project_root,
    )
    assert result.returncode == EXIT_FINDINGS, result.stderr
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 20
    for line in lines:
        record = json.loads(line)
        assert sorted(record) == ["features", "file", "label_hint", "tool"]
        assert len(record["features"]) == len(FEATURE_NAMES)
        assert record["label_hint"] == "injection"


def test_module_entry_point_all_functions(subprocess_env, project_root):
    target = SAFE_DIR / "s09_no_tool_decorators.py"
    clean = run_module(["scan", str(target)], subprocess_env, project_root)
    assert clean.returncode == EXIT_CLEAN, clean.stderr

    flagged = run_module(
        ["scan", str(target), "--all-functions"], subprocess_env, project_root
    )
    assert flagged.returncode == EXIT_FINDINGS, flagged.stderr
    assert "helper" in flagged.stdout


# ---------------------------------------------------------------------------
# In-process, for speed and coverage
# ---------------------------------------------------------------------------


def test_exit_code_is_clean_for_safe_fixtures(capsys):
    assert main(["scan", str(SAFE_DIR)]) == EXIT_CLEAN
    assert "0 high" in capsys.readouterr().out


def test_exit_code_signals_high_findings(capsys):
    assert main(["scan", str(VULNERABLE_DIR)]) == EXIT_FINDINGS
    capsys.readouterr()


def test_medium_only_findings_do_not_fail_the_gate(capsys, tmp_path):
    target = tmp_path / "m.py"
    target.write_text(
        'import pickle\n@tool\ndef run(q):\n    """D."""\n    pickle.loads(q)\n',
        encoding="utf-8",
    )
    assert main(["scan", str(target)]) == EXIT_CLEAN
    assert "MEDIUM" in capsys.readouterr().out


def test_missing_path_is_a_usage_error(capsys):
    assert main(["scan", "does/not/exist.py"]) == EXIT_ERROR
    assert "no such file" in capsys.readouterr().err


def test_json_output_is_stable_across_runs(capsys):
    main(["scan", str(VULNERABLE_DIR / "v03_intermediate_var.py"), "--json"])
    first = capsys.readouterr().out
    main(["scan", str(VULNERABLE_DIR / "v03_intermediate_var.py"), "--json"])
    assert capsys.readouterr().out == first


def test_human_output_renders_the_taint_path(capsys):
    main(["scan", str(VULNERABLE_DIR / "v03_intermediate_var.py")])
    out = capsys.readouterr().out
    assert "flow:" in out
    assert "cmd" in out
    assert "os.system()" in out
    assert "hops: 2" in out


def test_human_output_reports_unparseable_files(capsys, tmp_path):
    target = tmp_path / "broken.py"
    target.write_text("def broken(:\n    pass\n", encoding="utf-8")
    assert main(["scan", str(target)]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "parse failed" in out
    assert "unparseable" in out


def test_feature_names_subcommand(capsys):
    assert main(["feature-names"]) == EXIT_CLEAN
    assert json.loads(capsys.readouterr().out) == list(FEATURE_NAMES)


def test_features_label_hint_is_benign_for_clean_tools(capsys):
    main(["features", str(SAFE_DIR / "s02_hardcoded_command.py")])
    record = json.loads(capsys.readouterr().out.strip())
    assert record["label_hint"] == "benign"


def test_out_creates_missing_parent_directories(tmp_path):
    out = tmp_path / "nested" / "deeper" / "results.json"
    main(["scan", str(SAFE_DIR), "--json", "--out", str(out)])
    assert json.loads(out.read_text(encoding="utf-8"))


def test_no_subcommand_is_an_argparse_error():
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == EXIT_ERROR
