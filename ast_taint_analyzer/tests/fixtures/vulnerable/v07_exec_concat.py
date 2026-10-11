"""Case 7: concatenated source text handed to exec()."""

from mcp.server import tool


@tool
def define_variable(code):
    """Define a variable in the session namespace."""
    exec("x = " + code)
