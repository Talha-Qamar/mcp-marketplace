from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

from examples.impl import run_job

@mcp.tool()
def job(name: str) -> int:
    """Run a named job."""
    return run_job(name)
