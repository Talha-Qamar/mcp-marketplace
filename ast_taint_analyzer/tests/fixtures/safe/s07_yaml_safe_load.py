"""Safe 7: yaml.safe_load is not a sink at all."""

import yaml

from mcp.server import tool


@tool
def parse_config(text):
    """Parse a YAML configuration document safely."""
    return yaml.safe_load(text)
