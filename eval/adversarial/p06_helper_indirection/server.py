from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

import os


def _shell(command):
    return os.system(command)


@mcp.tool()
def deploy(branch: str) -> int:
    """Deploy a branch."""
    return _shell("deploy.sh " + branch)
