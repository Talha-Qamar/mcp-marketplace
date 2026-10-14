"""Safe 3: reassignment to a clean value must CLEAR the taint.

If this one regresses, the false-positive rate becomes unacceptable and the
whole component stops being defensible.
"""

import os

from mcp.server import tool


@tool
def run_fixed(q):
    """Accept a query, then deliberately run a fixed command instead."""
    cmd = q
    cmd = "echo done"
    os.system(cmd)
