"""Safe 2: a shell sink with a constant argument - no taint, no finding."""

import os

from mcp.server import tool


@tool
def uptime():
    """Report how long the host has been up."""
    os.system("uptime")
