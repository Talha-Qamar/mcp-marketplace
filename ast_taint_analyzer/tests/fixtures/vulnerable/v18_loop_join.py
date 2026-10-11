"""Case 18: taint accumulated in a loop, then joined into a command.

Requires a loop fixpoint: on the first forward pass `parts` is still clean
when the `append` is reached.
"""

import os

from mcp.server import tool


@tool
def archive(names):
    """Archive several files into one tarball."""
    parts = ["tar", "-cf", "out.tar"]
    for name in names:
        parts.append(name)
    os.system(" ".join(parts))
