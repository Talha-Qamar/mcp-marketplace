"""Prove we can find the tools before we try to analyse them."""

from __future__ import annotations

import pytest

from ast_taint.exceptions import ParseError
from ast_taint.extractor import (
    decorator_dotted_name,
    extract_docstring,
    extract_tools,
    param_names,
)

import ast


def names(source, all_functions=False):
    return [fn.name for fn in extract_tools(source, all_functions=all_functions)]


def test_plain_name_decorator():
    source = "@tool\ndef run(q):\n    pass\n"
    assert names(source) == ["run"]


def test_attribute_decorator():
    source = "@server.tool\ndef run(q):\n    pass\n"
    assert names(source) == ["run"]


def test_called_decorator():
    source = "@mcp.tool()\ndef run(q):\n    pass\n"
    assert names(source) == ["run"]


def test_called_decorator_with_kwargs():
    source = '@server.tool(name="x", description="y")\ndef run(q):\n    pass\n'
    assert names(source) == ["run"]


def test_deeply_nested_decorator():
    source = "@a.b.c.d.tool()\ndef run(q):\n    pass\n"
    assert names(source) == ["run"]


def test_decorator_on_a_constructed_object():
    source = '@FastMCP("demo").tool()\ndef run(q):\n    pass\n'
    assert names(source) == ["run"]


def test_register_tool_and_function_tool_aliases():
    source = (
        "@register_tool\ndef a():\n    pass\n\n"
        "@function_tool()\ndef b():\n    pass\n"
    )
    assert names(source) == ["a", "b"]


def test_async_function_is_found():
    source = "@tool\nasync def run(q):\n    pass\n"
    assert names(source) == ["run"]


def test_class_method_is_found():
    source = "class T:\n    @tool\n    def run(self, q):\n        pass\n"
    assert names(source) == ["run"]


def test_tool_registered_inside_another_function():
    source = (
        "def main():\n"
        "    @mcp.tool()\n"
        "    def add(a, b):\n"
        "        return a + b\n"
        "    return add\n"
    )
    assert names(source) == ["add"]


def test_tool_inside_a_try_block():
    source = (
        "try:\n"
        "    @tool\n"
        "    def run(q):\n"
        "        pass\n"
        "except ImportError:\n"
        "    pass\n"
    )
    assert names(source) == ["run"]


def test_undecorated_functions_are_ignored_by_default():
    source = "def helper(q):\n    pass\n"
    assert names(source) == []


def test_all_functions_mode_picks_up_undecorated_functions():
    source = "def helper(q):\n    pass\n\nclass T:\n    def m(self):\n        pass\n"
    assert names(source, all_functions=True) == ["helper", "m"]


def test_all_functions_mode_skips_nested_functions():
    source = "def outer():\n    def inner():\n        pass\n    return inner\n"
    assert names(source, all_functions=True) == ["outer"]


def test_results_are_sorted_by_line_number():
    source = (
        "@tool\ndef c():\n    pass\n\n"
        "@tool\ndef a():\n    pass\n\n"
        "@tool\ndef b():\n    pass\n"
    )
    assert names(source) == ["c", "a", "b"]


def test_syntax_error_raises_parse_error_with_position():
    with pytest.raises(ParseError) as excinfo:
        extract_tools("def broken(:\n    pass\n")
    assert excinfo.value.lineno == 1


def test_docstring_extraction():
    source = '@tool\ndef run(q):\n    """Run a query."""\n    pass\n'
    fn = extract_tools(source)[0]
    assert extract_docstring(fn) == "Run a query."


def test_docstring_absent_returns_none():
    source = "@tool\ndef run(q):\n    pass\n"
    fn = extract_tools(source)[0]
    assert extract_docstring(fn) is None


def test_param_names_drops_self():
    source = "class T:\n    @tool\n    def run(self, a, b):\n        pass\n"
    fn = extract_tools(source)[0]
    assert param_names(fn) == ["a", "b"]


def test_param_names_drops_cls():
    source = "class T:\n    @tool\n    def run(cls, a):\n        pass\n"
    fn = extract_tools(source)[0]
    assert param_names(fn) == ["a"]


def test_param_names_covers_every_parameter_kind():
    source = (
        "@tool\n"
        "def run(a, /, b, *args, c, **kwargs):\n"
        "    pass\n"
    )
    fn = extract_tools(source)[0]
    assert param_names(fn) == ["a", "b", "args", "c", "kwargs"]


@pytest.mark.parametrize(
    "decorator,expected",
    [
        ("@tool", "tool"),
        ("@server.tool", "server.tool"),
        ("@mcp.tool()", "mcp.tool"),
        ("@a.b.c.tool()", "a.b.c.tool"),
    ],
)
def test_decorator_dotted_name(decorator, expected):
    tree = ast.parse(decorator + "\ndef f():\n    pass\n")
    assert decorator_dotted_name(tree.body[0].decorator_list[0]) == expected


def test_decorator_dotted_name_unresolvable():
    tree = ast.parse('@registry["x"]\ndef f():\n    pass\n')
    assert decorator_dotted_name(tree.body[0].decorator_list[0]) is None


def test_every_vulnerable_fixture_exposes_exactly_one_tool(vulnerable_dir):
    from ast_taint import analyze_file

    for path in sorted(vulnerable_dir.glob("*.py")):
        analysis = analyze_file(path)
        assert analysis.parse_ok, path.name
        assert len(analysis.tools) == 1, path.name
        assert analysis.tools[0].docstring, path.name
