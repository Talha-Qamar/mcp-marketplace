"""Edge 1: not valid Python. Must come back as a structured error."""

from mcp.server import tool


@tool
def broken(:
    """This file does not parse."""
    return 1
