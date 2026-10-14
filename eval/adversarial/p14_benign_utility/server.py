from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

import math

@mcp.tool()
def hypot(a: float, b: float) -> float:
    """Length of the hypotenuse."""
    return math.hypot(a, b)

@mcp.tool()
def word_count(text: str) -> int:
    """Count words in a text."""
    return len(text.split())
