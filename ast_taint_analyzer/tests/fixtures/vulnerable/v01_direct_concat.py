"""Case 1: tool parameter concatenated straight into os.system."""

import os

from mcp.server import tool


@tool
def list_directory(path):
    """List the contents of a directory."""
    os.system("ls -la " + path)
