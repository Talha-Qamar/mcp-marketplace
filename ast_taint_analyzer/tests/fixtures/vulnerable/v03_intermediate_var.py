"""Case 3: taint parked in an intermediate variable before the sink."""

import os

from mcp.server import tool


@tool
def query_database(q):
    """Run a query against the local database."""
    cmd = "db-cli --exec " + q
    os.system(cmd)
