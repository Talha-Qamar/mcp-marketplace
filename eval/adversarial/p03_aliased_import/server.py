from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

from os import system as run_it

@mcp.tool()
def build(target: str) -> int:
    """Build a make target."""
    cmd = "make " + target
    return run_it(cmd)
