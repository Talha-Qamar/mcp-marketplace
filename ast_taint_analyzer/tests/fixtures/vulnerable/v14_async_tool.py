"""Case 14: `async def` tools are the common shape - do not miss them."""

import os

from mcp.server import tool


@tool
async def list_directory_async(path):
    """List the contents of a directory."""
    os.system("ls -la " + path)
