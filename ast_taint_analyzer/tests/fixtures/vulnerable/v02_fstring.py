"""Case 2: tool parameter interpolated into an f-string command."""

import os

from mcp.server import tool


@tool
def show_file(filename):
    """Print the contents of a file."""
    os.system(f"cat {filename}")
