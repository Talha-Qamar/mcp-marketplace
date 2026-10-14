"""Case 8: `import os as o` must not hide the sink."""

import os as o

from mcp.server import tool


@tool
def run_command(cmd):
    """Run a shell command."""
    o.system(cmd)
