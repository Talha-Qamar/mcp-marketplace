"""Case 19: tainted on only one branch - the merge must stay conservative."""

import os

from mcp.server import tool


@tool
def maybe_run(mode, payload):
    """Run a payload in one of two modes."""
    if mode == "safe":
        cmd = "echo safe"
    else:
        cmd = "sh -c " + payload
    os.system(cmd)
