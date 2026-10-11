"""Case 17: taint carried through %-formatting."""

import os

from mcp.server import tool


@tool
def list_directory(directory):
    """List a directory, building the command with %-formatting."""
    os.system("ls %s" % directory)
