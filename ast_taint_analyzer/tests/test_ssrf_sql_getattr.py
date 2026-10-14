"""SSRF and SQL injection sinks, and getattr() constant resolution (Mid 1 review)."""

from ast_taint.analyzer import analyze_source

HEADER = "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"


def hits(body: str):
    analysis = analyze_source(HEADER + body, "server.py")
    return [(h.sink_name, h.category.value, h.severity.value) for t in analysis.tools for h in t.hits]


def test_ssrf_when_the_url_starts_with_tool_input():
    assert hits("import requests\n@mcp.tool()\ndef f(url: str):\n    return requests.get(url).text\n") == [
        ("requests.get", "network", "medium")]
    assert hits("import httpx\n@mcp.tool()\ndef f(host: str):\n    return httpx.get(f'{host}/status')\n") == [
        ("httpx.get", "network", "medium")]


def test_tool_input_in_the_query_of_a_fixed_host_is_not_ssrf():
    assert hits("import requests\n@mcp.tool()\ndef f(q: str):\n"
                "    return requests.get(f'https://api.example.com/search?q={q}').text\n") == []
    assert hits("import requests\n@mcp.tool()\ndef f(q: str):\n"
                "    return requests.get('https://api.example.com/s', params={'q': q}).text\n") == []


def test_sql_built_from_tool_input_is_injection():
    for build in ("f\"SELECT * FROM t WHERE n = '{name}'\"",
                  "\"SELECT * FROM t WHERE n = '\" + name + \"'\"",
                  "\"SELECT * FROM t WHERE n = '%s'\" % name",
                  "\"SELECT * FROM t WHERE n = '{}'\".format(name)"):
        assert [h[1:] for h in hits(f"@mcp.tool()\ndef f(name: str):\n    return db.execute({build})\n")] == [
            ("sql", "medium")], build


def test_sql_through_a_variable():
    assert hits("@mcp.tool()\ndef f(name: str):\n    q = f'SELECT * FROM t WHERE n = {name}'\n    cur.execute(q)\n") == [
        ("cur.execute", "sql", "medium")]


def test_parameterised_and_whole_query_tools_are_not_injection():
    # parameterised: the value travels separately from the SQL text
    assert hits("@mcp.tool()\ndef f(name: str):\n    return db.execute('SELECT * FROM t WHERE n = ?', (name,))\n") == []
    # the tool's purpose is to run the caller's query: by design, not injection
    assert hits("@mcp.tool()\ndef f(query: str):\n    return db.execute(query)\n") == []


def test_getattr_with_a_constant_name_resolves_to_the_sink():
    assert hits("import os\n@mcp.tool()\ndef f(cmd: str):\n    fn = getattr(os, 'sys' + 'tem')\n    return fn(cmd)\n") == [
        ("os.system", "shell", "high")]
    assert hits("import os\n@mcp.tool()\ndef f(cmd: str):\n    return getattr(os, 'system')(cmd)\n") == [
        ("os.system", "shell", "high")]


def test_placeholder_lists_for_parameterised_queries_are_not_injection():
    assert hits("@mcp.tool()\ndef f(ids: list):\n"
                "    q = f\"SELECT * FROM t WHERE id IN ({', '.join('?' for _ in ids)})\"\n"
                "    return db.execute(q, ids)\n") == []
