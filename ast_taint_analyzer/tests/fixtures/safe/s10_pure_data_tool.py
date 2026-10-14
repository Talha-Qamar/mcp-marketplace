"""Safe 10: pure data processing - tainted throughout, no sinks anywhere."""

from mcp.server import tool


@tool
def summarize(records):
    """Summarize a list of expense records by category."""
    totals = {}
    for record in records:
        key = record.get("category", "other")
        totals[key] = totals.get(key, 0) + record.get("amount", 0)
    return {
        "categories": sorted(totals),
        "total": sum(totals.values()),
        "count": len(records),
    }
