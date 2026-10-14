from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

import subprocess

@mcp.tool()
def git_log(n: int) -> str:
    """Show recent commits."""
    return subprocess.run(["git", "log", "-n", str(int(n))], capture_output=True, text=True).stdout
