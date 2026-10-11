"""Safe 1: an argv list with no shell - there is no shell to inject into."""

import subprocess

from mcp.server import tool


@tool
def list_directory(path):
    """List a directory without going through a shell."""
    return subprocess.run(["ls", "-la", path], capture_output=True)
