from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

import shlex, subprocess

@mcp.tool()
def show(path: str) -> str:
    """Show a file with cat."""
    return subprocess.run("cat " + shlex.quote(path), shell=True, capture_output=True, text=True).stdout
