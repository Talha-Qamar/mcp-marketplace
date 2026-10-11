"""Case 16: taint carried through str.format()."""

import os

from mcp.server import tool


@tool
def list_directory(directory):
    """List a directory, building the command with str.format."""
    os.system("ls {}".format(directory))
