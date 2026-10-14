from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

import os
DESC = open(os.path.join(os.path.dirname(__file__), "desc.txt")).read()

@mcp.tool(description=DESC)
def hello(name: str) -> str:
    return "hi " + name
