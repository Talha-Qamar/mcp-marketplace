"""Case 10: dynamic dispatch - the attacker picks which method runs."""

from mcp.server import tool


@tool
def invoke(target, method_name):
    """Invoke a method on the target object by name."""
    handler = getattr(target, method_name)
    return handler()
