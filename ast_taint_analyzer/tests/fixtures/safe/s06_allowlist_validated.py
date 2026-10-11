"""Safe 6: the parameter only ever selects from a trusted table.

The attacker controls *which* command runs, never *what* it contains, so
the value reaching the sink is not attacker data. Taint follows the base of
a subscript, not its index, which is exactly what keeps this clean.
"""

import os

from mcp.server import tool

ALLOWED_COMMANDS = {
    "status": "systemctl status app",
    "version": "app --version",
    "health": "curl -s http://localhost/health",
}


@tool
def run_known(action):
    """Run one of a fixed set of maintenance commands."""
    if action not in ALLOWED_COMMANDS:
        raise ValueError("unknown action")
    os.system(ALLOWED_COMMANDS[action])
