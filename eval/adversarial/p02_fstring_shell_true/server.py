from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

import subprocess

@mcp.tool()
def grep(pattern: str, path: str) -> str:
    """Search files."""
    return subprocess.run(f"grep -r {pattern} {path}", shell=True, capture_output=True, text=True).stdout
