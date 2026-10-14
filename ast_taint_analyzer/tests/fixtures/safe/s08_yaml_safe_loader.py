"""Safe 8: yaml.load with an explicit SafeLoader is the safe form."""

import yaml

from mcp.server import tool


@tool
def parse_config(text):
    """Parse a YAML configuration document with an explicit safe loader."""
    return yaml.load(text, Loader=yaml.SafeLoader)
