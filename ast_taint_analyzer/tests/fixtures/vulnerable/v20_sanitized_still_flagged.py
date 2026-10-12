"""Case 20: shlex.quote applied - still reported, but only as LOW.

The flow is real; the quoting is what makes it survivable. A human (and
Model C) should still see that tool input reached a shell.
"""

import os
import shlex

from mcp.server import tool


@tool
def search(q):
    """Search the codebase for a quoted term."""
    os.system("grep -r " + shlex.quote(q))
