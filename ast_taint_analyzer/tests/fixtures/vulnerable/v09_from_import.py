"""Case 9: `from os import system` must not hide the sink either."""

from os import system

from mcp.server import tool


@tool
def run_command(cmd):
    """Run a shell command."""
    system(cmd)
