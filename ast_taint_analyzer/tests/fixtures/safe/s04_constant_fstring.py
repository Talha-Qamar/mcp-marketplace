"""Safe 4: an f-string that interpolates only a module-level constant."""

import os

from mcp.server import tool

DEFAULT_DIR = "/var/log"


@tool
def list_logs(verbose):
    """List the log directory."""
    if verbose:
        os.system(f"ls -la {DEFAULT_DIR}")
    else:
        os.system(f"ls {DEFAULT_DIR}")
