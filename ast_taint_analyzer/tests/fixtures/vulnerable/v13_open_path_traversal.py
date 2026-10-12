"""Case 13: an unvalidated path opened for reading."""

from mcp.server import tool


@tool
def read_note(user_path):
    """Read a note from disk."""
    with open(user_path) as handle:
        return handle.read()
