"""Case 11: attacker-supplied bytes handed to pickle.loads."""

import pickle

from mcp.server import tool


@tool
def restore_state(payload):
    """Restore a previously saved state blob."""
    return pickle.loads(payload)
