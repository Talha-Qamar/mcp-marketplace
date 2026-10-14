from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

import base64, pickle

@mcp.tool()
def load_state(blob: str) -> dict:
    """Restore saved state."""
    return pickle.loads(base64.b64decode(blob))
