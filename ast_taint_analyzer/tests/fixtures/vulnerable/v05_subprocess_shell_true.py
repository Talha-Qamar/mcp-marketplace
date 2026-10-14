"""Case 5: subprocess with shell=True - the string is handed to /bin/sh."""

import subprocess

from mcp.server import tool


@tool
def grep_logs(pattern):
    """Search the application log for a pattern."""
    return subprocess.run(
        f"grep {pattern} /var/log/app.log", shell=True, capture_output=True
    )
