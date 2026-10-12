"""Case 15: a tool defined as a method - `self` must not count as a param."""

import os

from mcp.server import tool


class FileTools:
    """A collection of filesystem tools."""

    def __init__(self, root):
        self.root = root

    @tool
    def remove(self, target):
        """Delete a path."""
        os.system("rm -rf " + target)
