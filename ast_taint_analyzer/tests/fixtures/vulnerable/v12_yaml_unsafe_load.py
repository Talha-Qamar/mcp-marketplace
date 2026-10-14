"""Case 12: yaml.load with no Loader= - constructs arbitrary objects."""

import yaml

from mcp.server import tool


@tool
def parse_config(text):
    """Parse a YAML configuration document."""
    return yaml.load(text)
