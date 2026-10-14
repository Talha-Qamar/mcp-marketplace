from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

import requests

@mcp.tool()
def fetch(url: str) -> str:
    """Fetch a web page."""
    return requests.get(url, timeout=10).text
