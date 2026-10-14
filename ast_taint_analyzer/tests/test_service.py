"""The contract wrapper (service.py) around the analyzer."""

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ast_service", ROOT / "service.py")
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)

SOURCE = '''import os
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")


@mcp.tool()
def run(q: str) -> int:
    """Run."""
    return os.system("run " + q)


@mcp.tool()
def safe(q: str) -> str:
    """Safe."""
    return q.upper()
'''


def bundle(files, tools=()):
    return {"files": files, "tools": list(tools)}


def py(path, content):
    return {"path": path, "language": "python", "content": content}


def test_findings_use_taxonomy_and_real_locations():
    tools = [{"tool_id": "s.py#run", "file": "s.py", "language": "python",
              "handler": {"name": "run", "start_line": 6, "end_line": 9}}]
    res = service.analyze(bundle([py("s.py", SOURCE)], tools), {})
    assert res["status"] == "ok"
    (f,) = res["findings"]
    assert f["threat"] == "command_injection" and f["cwe"] == "CWE-78"
    assert f["severity"] == "high" and f["score"] == 1.0
    assert f["location"]["file"] == "s.py" and f["location"]["line"] == 9
    assert f["location"]["function"] == {"name": "run", "start_line": 6, "end_line": 9}
    assert f["location"]["tool_id"] == "s.py#run"
    assert f["finding_id"].startswith("sha256:")


def test_not_applicable_without_python():
    res = service.analyze(bundle([{"path": "i.ts", "language": "typescript", "content": "x"}]), {})
    assert res["status"] == "not_applicable" and res["findings"] == []


def test_parse_failure_is_reported_not_raised():
    res = service.analyze(bundle([py("bad.py", "def (:\n")]), {})
    assert res["status"] == "error"
    assert any("parse failed" in n for n in res["coverage"]["notes"])


def test_deterministic():
    b = bundle([py("s.py", SOURCE)])
    assert json.dumps(service.analyze(b, {}), sort_keys=True) == json.dumps(service.analyze(b, {}), sort_keys=True)


def test_health_matches_identity():
    h = service.health()
    assert h["id"] == "ast_taint" and h["contract_version"] == "1"
    assert h["artifact_hash"].startswith("sha256:")
