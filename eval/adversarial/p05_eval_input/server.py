from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def calc(expression: str) -> str:
    """Evaluate a math expression."""
    return str(eval(expression))
