"""All detection knowledge, as data.

Nothing in this file is logic.  If a reviewer asks "what exactly do you
detect?", this is the single file to point at.  ``analyzer.py`` reads these
tables and never hard-codes a sink, sanitizer or decorator name.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, List, Optional, Tuple

from .models import SinkCategory

# --------------------------------------------------------------------------
# 1. Sink registry
# --------------------------------------------------------------------------
# dotted name -> (category, dangerous_arg_positions, dangerous_kwargs, conditional)
#
# Conditional semantics:
#   "shell_true"     - only a sink when the call has shell=True.  Without it
#                      the call passes an argv list, which is not a shell
#                      injection sink.
#   "no_safe_loader" - only a sink when Loader= is absent or is not one of
#                      SAFE_YAML_LOADERS.
SinkSpec = Tuple[SinkCategory, List[int], List[str], Optional[str]]

SINKS: Dict[str, SinkSpec] = {
    "os.system": (SinkCategory.SHELL, [0], [], None),
    "os.popen": (SinkCategory.SHELL, [0], [], None),
    "os.execv": (SinkCategory.SHELL, [0, 1], [], None),
    "os.execve": (SinkCategory.SHELL, [0, 1], [], None),
    "os.spawnl": (SinkCategory.SHELL, [1], [], None),
    "subprocess.run": (SinkCategory.SHELL, [0], ["args"], "shell_true"),
    "subprocess.call": (SinkCategory.SHELL, [0], ["args"], "shell_true"),
    "subprocess.check_call": (SinkCategory.SHELL, [0], ["args"], "shell_true"),
    "subprocess.check_output": (SinkCategory.SHELL, [0], ["args"], "shell_true"),
    "subprocess.Popen": (SinkCategory.SHELL, [0], ["args"], "shell_true"),
    "commands.getoutput": (SinkCategory.SHELL, [0], [], None),
    "eval": (SinkCategory.EXEC, [0], [], None),
    "exec": (SinkCategory.EXEC, [0], [], None),
    "compile": (SinkCategory.EXEC, [0], [], None),
    "getattr": (SinkCategory.DYNAMIC, [1], [], None),
    "setattr": (SinkCategory.DYNAMIC, [1], [], None),
    "__import__": (SinkCategory.DYNAMIC, [0], [], None),
    "importlib.import_module": (SinkCategory.DYNAMIC, [0], [], None),
    "pickle.loads": (SinkCategory.DESERIALIZE, [0], [], None),
    "pickle.load": (SinkCategory.DESERIALIZE, [0], [], None),
    "yaml.load": (SinkCategory.DESERIALIZE, [0], [], "no_safe_loader"),
    "marshal.loads": (SinkCategory.DESERIALIZE, [0], [], None),
    "open": (SinkCategory.FILE, [0], ["file"], None),
    "pathlib.Path": (SinkCategory.FILE, [0], [], None),
}

#: ``yaml.load(data, Loader=...)`` values whose final segment is in this set
#: are safe; anything else (including an absent Loader) is treated as unsafe.
SAFE_YAML_LOADERS: FrozenSet[str] = frozenset({"SafeLoader", "CSafeLoader"})


# --------------------------------------------------------------------------
# 2. Sanitizer registry
# --------------------------------------------------------------------------
# A sanitizer anywhere on the path marks the hit sanitized=True and drops its
# severity to LOW.  The hit is NOT suppressed - a human (and Model C) should
# still see that tainted data reached a sink, even in quoted form.
SANITIZERS: FrozenSet[str] = frozenset(
    {
        "shlex.quote",
        "shlex.split",
        "pipes.quote",
        "re.escape",
        "urllib.parse.quote",
        "os.path.basename",
        "html.escape",
    }
)


# --------------------------------------------------------------------------
# 3. Taint sources
# --------------------------------------------------------------------------
# The dominant source is "every parameter of the tool function" - MCP tool
# arguments are attacker-controlled by definition.  These are the secondary
# sources.
UNTRUSTED_CALLS: FrozenSet[str] = frozenset(
    {
        "input",
        "sys.argv",
        "os.environ.get",
        "os.getenv",
        "json.loads",  # only when its own argument is tainted
    }
)

#: Members of UNTRUSTED_CALLS that introduce taint only when one of their own
#: arguments is already tainted (they transform, they do not originate).
CONDITIONAL_UNTRUSTED_CALLS: FrozenSet[str] = frozenset({"json.loads"})

#: Members of UNTRUSTED_CALLS that originate taint unconditionally.
DIRECT_UNTRUSTED_CALLS: FrozenSet[str] = UNTRUSTED_CALLS - CONDITIONAL_UNTRUSTED_CALLS

#: Untrusted reads that are attribute/subscript expressions rather than calls,
#: e.g. ``sys.argv[1]`` and ``os.environ["HOME"]``.
UNTRUSTED_ATTRIBUTE_SOURCES: FrozenSet[str] = frozenset({"sys.argv", "os.environ"})

#: Label used as ``source_param`` when taint came from a secondary source.
UNTRUSTED_ORIGIN = "<untrusted>"


# --------------------------------------------------------------------------
# 4. Taint propagation
# --------------------------------------------------------------------------
# Calls whose return value carries the taint of their arguments.  Without
# these, a one-token wrapper such as ``str(q)`` or ``base64.b64decode(q)``
# would silently break the flow.
PROPAGATING_CALLS: FrozenSet[str] = frozenset(
    {
        "str",
        "repr",
        "format",
        "bytes",
        "bytearray",
        "list",
        "tuple",
        "set",
        "dict",
        "sorted",
        "reversed",
        "json.dumps",
        "base64.b64decode",
        "base64.b64encode",
        "base64.b32decode",
        "base64.b16decode",
        "base64.urlsafe_b64decode",
        "codecs.decode",
        "codecs.encode",
        "urllib.parse.unquote",
        "urllib.parse.unquote_plus",
        "os.path.join",
        "os.path.abspath",
        "os.path.normpath",
        "os.path.realpath",
        "os.path.expanduser",
        "os.path.expandvars",
        "shlex.join",
        "textwrap.dedent",
        "string.Template",
    }
)

#: Method names (matched on the attribute, not a dotted path) whose result
#: carries the taint of the receiver *or* of any argument.  This is what makes
#: ``"ls {}".format(d)`` and ``" ".join(parts)`` propagate.
STRING_TRANSFORM_METHODS: FrozenSet[str] = frozenset(
    {
        "format",
        "format_map",
        "join",
        "replace",
        "strip",
        "lstrip",
        "rstrip",
        "removeprefix",
        "removesuffix",
        "lower",
        "upper",
        "title",
        "capitalize",
        "casefold",
        "swapcase",
        "center",
        "ljust",
        "rjust",
        "zfill",
        "expandtabs",
        "translate",
        "encode",
        "decode",
        "split",
        "rsplit",
        "splitlines",
        "partition",
        "rpartition",
    }
)

#: Method names that mutate their receiver.  ``parts.append(tainted)`` taints
#: ``parts``.  This is container-level, not element-level: see README.
MUTATING_METHODS: FrozenSet[str] = frozenset(
    {
        "append",
        "extend",
        "insert",
        "add",
        "update",
        "setdefault",
        "write",
        "writelines",
        "put",
        "push",
    }
)


# --------------------------------------------------------------------------
# 5. Tool discovery
# --------------------------------------------------------------------------
# Matched on the LAST attribute segment, so ``@anything.tool()`` matches.
TOOL_DECORATORS: FrozenSet[str] = frozenset(
    {
        "tool",  # @tool
        "server.tool",  # @server.tool()
        "mcp.tool",  # @mcp.tool()
        "app.tool",
        "register_tool",
        "function_tool",
    }
)

#: Derived: the set of final segments actually compared against.
TOOL_DECORATOR_SUFFIXES: FrozenSet[str] = frozenset(
    name.rsplit(".", 1)[-1] for name in TOOL_DECORATORS
)


# --------------------------------------------------------------------------
# 6. Engine limits (bounds that keep the analysis total and terminating)
# --------------------------------------------------------------------------
#: Maximum expression nesting depth walked before giving up on a subtree.
MAX_EXPR_DEPTH = 100

#: Maximum silent passes over a loop body while chasing the taint fixpoint.
MAX_LOOP_PASSES = 4

#: Maximum number of variable names recorded in a taint path.
MAX_PATH_LEN = 16

#: Directory names skipped by ``analyze_repo``.
SKIP_DIR_NAMES: FrozenSet[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".nox",
        ".venv",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "build",
        "dist",
        "env",
        "node_modules",
        "site-packages",
        "tests",
        "venv",
    }
)
