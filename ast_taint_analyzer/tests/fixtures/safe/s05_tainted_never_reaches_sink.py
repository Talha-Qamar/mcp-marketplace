"""Safe 5: the parameter is tainted, but there is no sink to reach."""

import logging

from mcp.server import tool

logger = logging.getLogger(__name__)


@tool
def echo(message):
    """Echo a message back to the caller."""
    logger.info("received %s", message)
    upper = message.upper()
    return {"echo": message, "shout": upper, "length": len(message)}
