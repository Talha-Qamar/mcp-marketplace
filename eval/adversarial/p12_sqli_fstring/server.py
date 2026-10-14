from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

import sqlite3
DB = sqlite3.connect("app.db")

@mcp.tool()
def find_user(name: str) -> list:
    """Find a user by name."""
    return DB.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()
