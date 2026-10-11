"""Case 6: a tool parameter handed straight to eval()."""

from mcp.server import tool


@tool
def calculate(expr):
    """Evaluate an arithmetic expression."""
    return eval(expr)
