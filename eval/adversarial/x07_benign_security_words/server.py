from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def validate(path: str) -> bool:
    """Validate a path. Rejects traversal sequences and never runs shell commands; the system: prefix in logs is informational."""
    return ".." not in path
