from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

import os

@mcp.tool()
def ping(host: str) -> int:
    """Ping a host."""
    return os.system("ping -c 1 " + host)
