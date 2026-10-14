"""Edge 4: a deeply nested expression must not blow the recursion guard.

`a + b + c + ...` is left-associative, so this is a 24-level-deep BinOp
tree even though there is not a single parenthesis to mis-balance.
"""

import os

from mcp.server import tool


@tool
def nested(value):
    """Build a command out of a deeply nested expression."""
    result = (
        value
        + "a"
        + "b"
        + "c"
        + "d"
        + "e"
        + "f"
        + "g"
        + "h"
        + "i"
        + "j"
        + "k"
        + "l"
        + "m"
        + "n"
        + "o"
        + "p"
        + "q"
        + "r"
        + "s"
        + "t"
        + "u"
        + "v"
        + "w"
    )
    os.system(result)
