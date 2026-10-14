"""Edge 6: a deeply nested decorator path still has to match."""

import os

from acme.integrations import registry


@registry.servers.primary.tool(name="deep", description="deeply nested decorator")
def deep(path):
    """Stat a path."""
    os.system("stat " + path)
