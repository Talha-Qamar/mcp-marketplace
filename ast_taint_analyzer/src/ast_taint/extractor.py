"""Find the tool functions in a module.

The same extraction pass feeds both models: :func:`collect_tool_functions`
gives the code view (Model B, via the taint engine) and
:func:`extract_docstring` gives the text view (Model A).
"""

from __future__ import annotations

import ast
from typing import List, Optional, Sequence, Union

from .config import TOOL_DECORATOR_SUFFIXES
from .exceptions import ParseError

FunctionNode = Union[ast.FunctionDef, ast.AsyncFunctionDef]

#: Compound statements whose bodies may contain module-level tool definitions
#: (``if TYPE_CHECKING:``, ``try: ... except ImportError:``, ``with`` blocks).
_BODY_FIELDS = ("body", "orelse", "finalbody")


def parse_module(source: str, file_path: str = "<string>") -> ast.Module:
    """``ast.parse`` with a structured error.

    The analysed code is parsed, never compiled and never executed.
    """
    try:
        return ast.parse(source)
    except SyntaxError as exc:
        raise ParseError(
            exc.msg or "syntax error",
            lineno=exc.lineno,
            col_offset=exc.offset,
            file_path=file_path,
        ) from exc
    except ValueError as exc:  # e.g. source containing a null byte
        raise ParseError(str(exc) or "invalid source", file_path=file_path) from exc


def decorator_dotted_name(decorator: ast.expr) -> Optional[str]:
    """Resolve a decorator expression to a dotted name.

    Handles the three shapes the spec requires - ``@tool`` (``ast.Name``),
    ``@server.tool`` (``ast.Attribute``) and ``@server.tool()`` /
    ``@tool(name="x")`` (``ast.Call`` wrapping either) - plus arbitrarily
    deep nesting such as ``@a.b.c.tool()``.
    """
    node = decorator
    if isinstance(node, ast.Call):
        node = node.func

    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif not parts:
        # Something we cannot name at all, e.g. ``@registry["x"]``.
        return None
    # When the chain bottoms out in a call or subscript (``@FastMCP("x").tool()``)
    # we still know the trailing segments, which is all the match needs.
    parts.reverse()
    return ".".join(parts)


def is_tool_function(node: FunctionNode) -> bool:
    """True when any decorator's final segment is a known tool decorator."""
    for decorator in node.decorator_list:
        dotted = decorator_dotted_name(decorator)
        if dotted and dotted.rsplit(".", 1)[-1] in TOOL_DECORATOR_SUFFIXES:
            return True
    return False


def _child_bodies(node: ast.stmt) -> List[Sequence[ast.stmt]]:
    bodies: List[Sequence[ast.stmt]] = []
    for field in _BODY_FIELDS:
        value = getattr(node, field, None)
        if isinstance(value, list):
            bodies.append(value)
    for handler in getattr(node, "handlers", []) or []:
        bodies.append(handler.body)
    for case in getattr(node, "cases", []) or []:  # ast.Match, Python 3.10+
        bodies.append(case.body)
    return bodies


def _collect(
    body: Sequence[ast.stmt],
    out: List[FunctionNode],
    require_decorator: bool,
    descend_functions: bool,
) -> None:
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not require_decorator or is_tool_function(node):
                out.append(node)
            if descend_functions:
                _collect(node.body, out, require_decorator, descend_functions)
        elif isinstance(node, ast.ClassDef):
            _collect(node.body, out, require_decorator, descend_functions)
        else:
            for sub in _child_bodies(node):
                _collect(sub, out, require_decorator, descend_functions)


def collect_tool_functions(
    tree: ast.Module, all_functions: bool = False
) -> List[FunctionNode]:
    """Return the function nodes to analyse, sorted by source position.

    Default mode returns only decorated tools, and looks for them at module
    level, inside classes, inside ``if``/``try``/``with`` blocks and inside
    other functions (FastMCP servers often register tools from inside
    ``main()``).

    ``all_functions=True`` is the fallback for repositories that do not use
    decorators: it returns every module-level function and class method, but
    not functions nested inside other functions - those are already analysed
    as part of their enclosing function's body.
    """
    found: List[FunctionNode] = []
    if all_functions:
        _collect(tree.body, found, require_decorator=False, descend_functions=False)
    else:
        _collect(tree.body, found, require_decorator=True, descend_functions=True)

    deduped: List[FunctionNode] = []
    seen = set()
    for node in found:
        key = id(node)
        if key not in seen:
            seen.add(key)
            deduped.append(node)
    deduped.sort(key=lambda n: (n.lineno, n.col_offset, n.name))
    return deduped


def extract_tools(source: str, all_functions: bool = False) -> List[FunctionNode]:
    """Parse ``source`` and return its tool-decorated function nodes.

    Raises :class:`~ast_taint.exceptions.ParseError` on invalid syntax.
    """
    tree = parse_module(source)
    return collect_tool_functions(tree, all_functions=all_functions)


def extract_docstring(fn: FunctionNode) -> Optional[str]:
    """The tool description - Model A consumes this.  ``None`` if absent."""
    return ast.get_docstring(fn, clean=True)


def param_names(fn: FunctionNode) -> List[str]:
    """Declared parameters in source order, with a leading self/cls dropped.

    Includes positional-only, positional-or-keyword, ``*args``,
    keyword-only and ``**kwargs``.
    """
    args = fn.args
    names: List[str] = []
    for arg in list(getattr(args, "posonlyargs", []) or []) + list(args.args):
        names.append(arg.arg)
    if args.vararg is not None:
        names.append(args.vararg.arg)
    for arg in args.kwonlyargs:
        names.append(arg.arg)
    if args.kwarg is not None:
        names.append(args.kwarg.arg)
    if names and names[0] in ("self", "cls"):
        names = names[1:]
    return names
