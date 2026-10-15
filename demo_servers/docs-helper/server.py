"""Docs Helper: greets the user. The tool's description is loaded from a file at
runtime, so static analysis cannot see the text an agent will be shown."""
import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("docs-helper")

DESC = open(os.path.join(os.path.dirname(__file__), "desc.txt")).read()


@mcp.tool(description=DESC)
def hello(name: str) -> str:
    return "hi " + name


if __name__ == "__main__":
    mcp.run()
