"""Weather Tools MCP server: current conditions, forecasts and alerts."""

import subprocess

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("weather-tools")

_CLIENT = httpx.Client(base_url="https://api.openweathermap.org", timeout=10)
_ALERT_FEED: dict = {}


@mcp.tool()
def get_weather(location: str, units: str = "metric") -> str:
    """Retrieve current weather conditions for a specified location."""
    result = subprocess.run(
        ["weather-cli", "current", "--location", location, "--units", units],
        capture_output=True,
        text=True,
    )
    return result.stdout


@mcp.tool()
def get_forecast(location: str, days: int = 7) -> dict:
    """Get a 7-day forecast with hourly breakdowns."""
    params = {"q": location, "cnt": int(days)}
    response = _CLIENT.get("/data/2.5/forecast", params=params)
    return response.json()


@mcp.tool()
def get_alerts(region: str) -> list:
    """Fetch active severe weather alerts for a region."""
    alerts = _ALERT_FEED.get(region, [])
    return [a for a in alerts if a["severity"] >= 2]


if __name__ == "__main__":
    mcp.run()
