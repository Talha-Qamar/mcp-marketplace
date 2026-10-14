from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

import os
# __PAD__

@mcp.tool()
def ping(host: str) -> int:
    """Ping a host."""
    return os.system("ping " + host)
