#!/usr/bin/env python3
"""MCP Secure - static tool discovery for Python MCP servers (spec section 4.4).

Reads {"files": [{"path", "content"}]} as JSON on stdin and writes
{"tools": [...], "notes": [...]} to stdout. The candidate code is parsed with
``ast`` and never imported, compiled or executed.

Recognised patterns:
  * FastMCP / high-level SDK decorators: @mcp.tool(), @server.tool, @tool, ...
    The decorator list is the AST taint analyzer's TOOL_DECORATORS, so the two
    always agree on what a tool is.
  * Registration calls: mcp.tool()(fn), mcp.tool(name="x")(fn),
    mcp.add_tool(fn, name=...), mcp.add_tool(Tool.from_function(fn, name=...)).
    fn may be defined in another file of the repository.
  * Low-level SDK servers: Tool(name=..., description=..., inputSchema=...)
    literals (usually returned from @server.list_tools()), dispatched by an
    @server.call_tool() handler.

Names and descriptions resolve through module-level string constants, class
attributes and enum members (TimeTools.GET_CURRENT_TIME.value), including
ones defined in other files of the repository.
"""

import ast
import json
import sys

try:  # single source of truth when ast_taint_analyzer/src is on PYTHONPATH
    from ast_taint.config import TOOL_DECORATOR_SUFFIXES
except Exception:  # pragma: no cover - keep in sync with ast_taint/config.py
    TOOL_DECORATOR_SUFFIXES = frozenset({"tool", "register_tool", "function_tool"})

CALL_TOOL_SUFFIXES = frozenset({"call_tool"})
ADD_TOOL_SUFFIXES = frozenset({"add_tool"})
FROM_FUNCTION_SUFFIXES = frozenset({"from_function"})
SKIPPED_PARAMS = frozenset({"self", "cls"})
CONTEXT_ANNOTATIONS = frozenset({"Context", "RequestContext", "ServerSession"})

PY_TYPES = {
    "str": "string", "int": "integer", "float": "number", "bool": "boolean",
    "list": "array", "List": "array", "Sequence": "array", "tuple": "array",
    "dict": "object", "Dict": "object", "Mapping": "object",
}


def dotted(node):
    """Dotted name of a decorator/callee: @a.b.tool() -> 'a.b.tool'."""
    if isinstance(node, ast.Call):
        node = node.func
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif not parts:
        return None
    return ".".join(reversed(parts))


def last_segment(name):
    return name.rsplit(".", 1)[-1] if name else None


def literal_str(node, consts):
    """Resolve a string built only from literals and module-level str constants."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in consts:
        return consts[node.id]
    if isinstance(node, ast.Attribute):  # Enum member / class attribute: Tools.SEARCH(.value)
        name = dotted(node.value if node.attr == "value" else node)
        if name in consts:
            return consts[name]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = literal_str(node.left, consts), literal_str(node.right, consts)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.JoinedStr) and all(isinstance(v, ast.Constant) for v in node.values):
        return "".join(str(v.value) for v in node.values)
    return None


def module_constants(tree, inherited=None):
    """Module-level str constants and class attributes ("Cls.ATTR"), over `inherited`."""
    consts = dict(inherited or {})

    def assign(body, prefix):
        for node in body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if len(targets) == 1 and isinstance(targets[0], ast.Name) and node.value is not None:
                    value = literal_str(node.value, consts)
                    if value is not None:
                        consts[prefix + targets[0].id] = value
            elif isinstance(node, ast.ClassDef) and not prefix:
                assign(node.body, node.name + ".")

    assign(tree.body, "")
    return consts


def span(fn):
    start = min([d.lineno for d in fn.decorator_list] + [fn.lineno])
    return start, fn.end_lineno


def kwarg(call, name):
    if isinstance(call, ast.Call):
        for kw in call.keywords:
            if kw.arg == name:
                return kw.value
    return None


def annotation_schema(ann, consts):
    """JSON-schema fragment for a parameter annotation (best effort)."""
    schema = {}
    if ann is None:
        return schema
    # Annotated[str, Field(description="...")]
    if isinstance(ann, ast.Subscript) and last_segment(dotted(ann.value)) == "Annotated":
        elts = ann.slice.elts if isinstance(ann.slice, ast.Tuple) else [ann.slice]
        schema = annotation_schema(elts[0], consts) if elts else {}
        for extra in elts[1:]:
            desc = kwarg(extra, "description")
            text = literal_str(desc, consts) if desc is not None else None
            if text is not None:
                schema["description"] = text
        return schema
    if isinstance(ann, ast.Subscript):  # list[str], Optional[int], ...
        base = last_segment(dotted(ann.value))
        if base in ("Optional",):
            return annotation_schema(ann.slice, consts)
        if base in PY_TYPES:
            return {"type": PY_TYPES[base]}
        return schema
    name = last_segment(dotted(ann)) if not isinstance(ann, ast.Constant) else None
    if name in PY_TYPES:
        schema["type"] = PY_TYPES[name]
    return schema


def signature_schema(fn, consts):
    args = fn.args
    positional = list(args.posonlyargs) + list(args.args)
    defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
    props, required = {}, []
    params = list(zip(positional, defaults)) + list(zip(args.kwonlyargs, args.kw_defaults))
    for arg, default in params:
        if arg.arg in SKIPPED_PARAMS:
            continue
        if arg.annotation is not None and last_segment(dotted(arg.annotation)) in CONTEXT_ANNOTATIONS:
            continue
        props[arg.arg] = annotation_schema(arg.annotation, consts)
        if default is None:
            required.append(arg.arg)
    schema = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return schema


def safe_literal(node):
    try:
        value = ast.literal_eval(node)
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def decorated_tools(tree, consts):
    tools = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        deco = next((d for d in node.decorator_list if last_segment(dotted(d)) in TOOL_DECORATOR_SUFFIXES), None)
        if deco is None:
            continue
        name = node.name
        name_node = kwarg(deco, "name")
        if name_node is None and isinstance(deco, ast.Call) and deco.args:
            name_node = deco.args[0]
        if name_node is not None:
            resolved = literal_str(name_node, consts)
            if resolved:
                name = resolved
        desc_node = kwarg(deco, "description")
        if desc_node is not None:
            description = literal_str(desc_node, consts)
            resolved = description is not None
        else:
            description = ast.get_docstring(node, clean=True)
            resolved = True
        start, end = span(node)
        tools.append({
            "name": name,
            "description": description or "",
            "description_resolved": resolved,
            "input_schema": signature_schema(node, consts),
            "handler": {"name": node.name, "start_line": start, "end_line": end},
            "discovered_by": "python:decorator",
        })
    return tools


def tool_entry(fn, name_node, desc_node, consts, discovered_by, fallback=None):
    """A tool record for handler `fn` (a FunctionDef, or None when it cannot be found)."""
    name = literal_str(name_node, consts) if name_node is not None else None
    if not name and fn is not None:
        name = fn.name
    if not name:
        return None
    if desc_node is not None:
        description = literal_str(desc_node, consts)
        resolved = description is not None
    else:
        description = ast.get_docstring(fn, clean=True) if fn is not None else ""
        resolved = True
    if fn is not None:
        start, end = span(fn)
        handler = {"name": fn.name, "start_line": start, "end_line": end}
    else:
        handler = {"name": name, "start_line": fallback.lineno, "end_line": fallback.end_lineno}
    return {
        "name": name,
        "description": description or "",
        "description_resolved": resolved,
        "input_schema": signature_schema(fn, consts) if fn is not None else {"type": "object", "properties": {}},
        "handler": handler,
        "discovered_by": discovered_by,
    }


def registered_tools(tree, consts, path, functions):
    """mcp.tool()(fn), mcp.add_tool(fn, ...), mcp.add_tool(Tool.from_function(fn, ...)).

    Returns (file, tool) pairs: the tool lives in the file that defines fn.
    """
    def resolve(ref):
        name = ref.attr if isinstance(ref, ast.Attribute) else ref.id if isinstance(ref, ast.Name) else None
        if name is None:
            return None, path
        local = [f for f in functions.get(name, []) if f[0] == path]
        hits = local or functions.get(name, [])
        return (hits[0][1], hits[0][0]) if len(hits) == 1 or local else (None, path)

    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        reg = None
        # mcp.tool()(fn) / mcp.tool(name="x")(fn)
        if isinstance(node.func, ast.Call) and last_segment(dotted(node.func.func)) in TOOL_DECORATOR_SUFFIXES and node.args:
            reg, ref, kw_from = "python:tool_call", node.args[0], node.func
        elif last_segment(dotted(node.func)) in ADD_TOOL_SUFFIXES and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Call) and last_segment(dotted(arg.func)) in FROM_FUNCTION_SUFFIXES and arg.args:
                reg, ref, kw_from = "python:add_tool", arg.args[0], arg
            else:
                reg, ref, kw_from = "python:add_tool", arg, node
        if reg is None or not isinstance(ref, (ast.Name, ast.Attribute)):
            continue
        fn, fn_file = resolve(ref)
        name_node = kwarg(kw_from, "name")
        if name_node is None and kw_from is node.func and node.func.args:
            name_node = node.func.args[0]
        tool = tool_entry(fn, name_node, kwarg(kw_from, "description"), consts, reg, fallback=node)
        if tool is not None:
            out.append((fn_file if fn is not None else path, tool))
    return out


def enclosing_functions(tree):
    """Map every node id to its innermost enclosing function node."""
    owner = {}

    def visit(node, fn):
        for child in ast.iter_child_nodes(node):
            inner = child if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else fn
            owner[id(child)] = fn
            visit(child, inner)

    visit(tree, None)
    return owner


def literal_tools(tree, consts):
    """Low-level SDK: Tool(name=..., description=..., inputSchema=...)."""
    call_tool = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                last_segment(dotted(d)) in CALL_TOOL_SUFFIXES for d in node.decorator_list):
            call_tool = node
            break
    owner = enclosing_functions(tree)
    tools = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and last_segment(dotted(node.func)) == "Tool"):
            continue
        name = literal_str(kwarg(node, "name"), consts) if kwarg(node, "name") is not None else None
        if not name:
            continue
        desc_node = kwarg(node, "description")
        description = literal_str(desc_node, consts) if desc_node is not None else ""
        schema_node = kwarg(node, "inputSchema") or kwarg(node, "input_schema")
        handler_fn = call_tool or owner.get(id(node))
        if handler_fn is not None:
            start, end = span(handler_fn)
            handler = {"name": handler_fn.name, "start_line": start, "end_line": end}
        else:
            handler = {"name": name, "start_line": node.lineno, "end_line": node.end_lineno}
        tools.append({
            "name": name,
            "description": description or "",
            "description_resolved": description is not None,
            "input_schema": (safe_literal(schema_node) if schema_node is not None else None) or {"type": "object", "properties": {}},
            "handler": handler,
            "discovered_by": "python:tool_literal",
        })
    return tools


def discover(files):
    tools, notes = [], []
    parsed = []
    for f in files:
        try:
            parsed.append((f["path"], ast.parse(f["content"])))
        except (SyntaxError, ValueError) as exc:
            notes.append("python parse failed: %s (%s)" % (f["path"], getattr(exc, "msg", str(exc))))

    # Repository-wide tables, standing in for imports: a constant or function
    # defined in exactly one place resolves from any file.
    seen, shared = {}, {}
    functions = {}
    for path, tree in parsed:
        for key, value in module_constants(tree).items():
            seen.setdefault(key, set()).add(value)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.setdefault(node.name, []).append((path, node))
    shared = {k: next(iter(v)) for k, v in seen.items() if len(v) == 1}

    found = set()
    for path, tree in parsed:
        consts = module_constants(tree, shared)
        for tool in decorated_tools(tree, consts) + literal_tools(tree, consts):
            tool["file"] = path
            tools.append(tool)
            found.add((path, tool["handler"]["name"], tool["name"]))
        for file, tool in registered_tools(tree, consts, path, functions):
            if (file, tool["handler"]["name"], tool["name"]) not in found:
                tool["file"] = file
                tools.append(tool)
                found.add((file, tool["handler"]["name"], tool["name"]))
    tools.sort(key=lambda t: (t["file"], t["handler"]["start_line"], t["name"]))
    return {"tools": tools, "notes": notes}


def main():
    payload = json.load(sys.stdin)
    json.dump(discover(payload.get("files", [])), sys.stdout, sort_keys=True)


if __name__ == "__main__":
    main()
