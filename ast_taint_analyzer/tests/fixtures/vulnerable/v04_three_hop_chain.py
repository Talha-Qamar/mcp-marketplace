"""Case 4: a three-assignment chain - indirect enough to drop to MEDIUM."""

import os

from mcp.server import tool


@tool
def chained_command(q):
    """Build a command through several intermediate steps."""
    a = q
    b = a + "-suffix"
    c = "run " + b
    os.system(c)
