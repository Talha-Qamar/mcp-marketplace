from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

import os
BASE = "/srv/notes"

@mcp.tool()
def read_note(name: str) -> str:
    """Read a note."""
    with open(os.path.join(BASE, name)) as f:
        return f.read()
