"""The taint engine.

Reads the AST of an MCP server's tool functions and decides whether
attacker-controlled input can reach a dangerous execution sink.

The analysed code is parsed only.  Nothing in this module imports,
compiles, evaluates or executes it.

Analysis shape: flow-sensitive within a function (statements are processed
in source order), path-INsensitive across branches (both arms are analysed
and their taint states merged conservatively), and intra-procedural (taint
does not follow into helper functions).  Over-approximation is deliberate -
a borderline flag routes to REVIEW, a missed flow does not.
"""

from __future__ import annotations

import ast
import hashlib
import io
import os
import tokenize
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

from .config import (
    CONDITIONAL_UNTRUSTED_CALLS,
    DIRECT_UNTRUSTED_CALLS,
    MAX_EXPR_DEPTH,
    MAX_LOOP_PASSES,
    MAX_PATH_LEN,
    MUTATING_METHODS,
    PROPAGATING_CALLS,
    SAFE_YAML_LOADERS,
    SANITIZERS,
    SINKS,
    SKIP_DIR_NAMES,
    STRING_TRANSFORM_METHODS,
    UNTRUSTED_ATTRIBUTE_SOURCES,
    UNTRUSTED_ORIGIN,
)
from .exceptions import ParseError
from .extractor import (
    FunctionNode,
    collect_tool_functions,
    extract_docstring,
    param_names,
    parse_module,
)
from .models import (
    SEVERITY_RANK,
    FileAnalysis,
    FlowFacts,
    Severity,
    SinkCategory,
    SinkHit,
    ToolAnalysis,
    max_severity,
    sort_categories,
)

__all__ = [
    "TaintInfo",
    "analyze_source",
    "analyze_file",
    "analyze_repo",
    "build_alias_map",
    "read_source",
]

_MATCH_SUPPORTED = hasattr(ast, "Match")
_TRYSTAR_SUPPORTED = hasattr(ast, "TryStar")


# --------------------------------------------------------------------------
# Taint lattice
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TaintInfo:
    """What is known about one tainted variable at one program point."""

    origin: str  # the tool parameter the taint came from
    hops: int  # assignments traversed since the origin
    path: Tuple[str, ...]  # ordered variable names along the flow
    sanitized: bool  # a known sanitizer was applied on the path

    @property
    def sort_key(self) -> Tuple[bool, int, Tuple[str, ...], str]:
        # Unsanitized beats sanitized, then fewer hops, then lexical order.
        # Purely a tie-break so merges are order-independent and reproducible.
        return (self.sanitized, self.hops, self.path, self.origin)


def _merge(a: Optional[TaintInfo], b: Optional[TaintInfo]) -> Optional[TaintInfo]:
    """Join two taint facts, preferring the more alarming one."""
    if a is None:
        return b
    if b is None:
        return a
    return a if a.sort_key <= b.sort_key else b


def _merge_all(infos: Iterable[Optional[TaintInfo]]) -> Optional[TaintInfo]:
    best: Optional[TaintInfo] = None
    for info in infos:
        best = _merge(best, info)
    return best


def _advance(info: Optional[TaintInfo], name: str) -> Optional[TaintInfo]:
    """Record one more assignment hop into the variable ``name``."""
    if info is None:
        return None
    path = info.path
    if (not path or path[-1] != name) and len(path) < MAX_PATH_LEN:
        path = path + (name,)
    return TaintInfo(
        origin=info.origin,
        hops=info.hops + 1,
        path=path,
        sanitized=info.sanitized,
    )


def _untrusted() -> TaintInfo:
    return TaintInfo(
        origin=UNTRUSTED_ORIGIN, hops=0, path=(UNTRUSTED_ORIGIN,), sanitized=False
    )


def _severity(category: SinkCategory, hops: int, sanitized: bool) -> Severity:
    """The frozen severity table (plan section 5.5).

    A sanitized flow is always LOW, whatever the category - that is what
    fixture ``v20`` pins down.  (Section 3.2 of the plan described a
    "drop one level" rule instead; section 5.5 and the fixture win, and the
    conflict is noted in the README.)
    """
    if sanitized:
        return Severity.LOW
    if category in (SinkCategory.SHELL, SinkCategory.EXEC) and hops <= 2:
        return Severity.HIGH
    return Severity.MEDIUM


# --------------------------------------------------------------------------
# Import alias resolution
# --------------------------------------------------------------------------


def build_alias_map(tree: ast.Module) -> Dict[str, str]:
    """Map locally bound names to their fully qualified dotted names.

    ``import os as o``        -> {"o": "os"}
    ``from os import system`` -> {"system": "os.system"}

    Without this, a one-token rename defeats the whole analyzer.  The scan
    covers nested imports too (MCP tools often ``import os`` inside the
    function body).
    """
    aliases: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    head = alias.name.split(".")[0]
                    aliases[head] = head
        elif isinstance(node, ast.ImportFrom):
            if node.module is None or node.level:
                continue  # relative import - cannot resolve a stable dotted name
            for alias in node.names:
                if alias.name == "*":
                    continue
                aliases[alias.asname or alias.name] = node.module + "." + alias.name
    return aliases


# --------------------------------------------------------------------------
# Per-function engine
# --------------------------------------------------------------------------


class _FunctionAnalyzer:
    """Taint propagation and sink detection for a single function body."""

    def __init__(
        self,
        fn: FunctionNode,
        lines: Sequence[str],
        aliases: Dict[str, str],
    ) -> None:
        self.fn = fn
        self.lines = lines
        self.aliases = aliases

        self.params: List[str] = param_names(fn)
        self.tainted: Dict[str, TaintInfo] = {}
        self.ever_tainted: Set[str] = set()
        self.const_bools: Dict[str, bool] = {}
        self.hits: List[SinkHit] = []

        self.has_fstring_flow = False
        self.has_concat_flow = False
        self.shell_true_present = False
        self._silent = False  # True during loop fixpoint passes

    # -- entry point -------------------------------------------------------

    def run(self) -> None:
        for name in self.params:
            self._set(name, TaintInfo(origin=name, hops=0, path=(name,), sanitized=False))
        self._visit_body(self.fn.body)

    # -- taint state -------------------------------------------------------

    def _set(self, name: str, info: Optional[TaintInfo]) -> None:
        if info is None:
            self.tainted.pop(name, None)
        else:
            self.tainted[name] = info
            self.ever_tainted.add(name)

    def _snapshot(self) -> Tuple:
        return tuple(
            sorted(
                (name, info.origin, info.hops, info.path, info.sanitized)
                for name, info in self.tainted.items()
            )
        )

    @staticmethod
    def _merge_states(states: Sequence[Dict[str, TaintInfo]]) -> Dict[str, TaintInfo]:
        merged: Dict[str, TaintInfo] = {}
        for state in states:
            for name, info in state.items():
                merged[name] = _merge(merged.get(name), info)
        return merged

    # -- statements --------------------------------------------------------

    def _visit_body(self, body: Sequence[ast.stmt]) -> None:
        for stmt in body:
            self._visit_stmt(stmt)

    def _visit_stmt(self, node: ast.stmt) -> None:
        if isinstance(node, ast.Assign):
            self._scan_expr(node.value)
            info = self._taint_of(node.value)
            for target in node.targets:
                self._scan_target(target)
                self._bind(target, info)
            self._record_const_bool(node)

        elif isinstance(node, ast.AnnAssign):
            info = None
            if node.value is not None:
                self._scan_expr(node.value)
                info = self._taint_of(node.value)
            self._scan_target(node.target)
            self._bind(node.target, info)

        elif isinstance(node, ast.AugAssign):
            self._scan_expr(node.value)
            rhs = self._taint_of(node.value)
            current = (
                self.tainted.get(node.target.id)
                if isinstance(node.target, ast.Name)
                else None
            )
            info = _merge(current, rhs)
            if info is not None and isinstance(node.op, ast.Add):
                self.has_concat_flow = True
            self._scan_target(node.target)
            self._bind(node.target, info)

        elif isinstance(node, ast.Expr):
            self._scan_expr(node.value)
            self._taint_of(node.value)

        elif isinstance(node, ast.Return):
            # Taint escaping through the return value is out of scope, but a
            # sink inside the returned expression is very much in scope.
            if node.value is not None:
                self._scan_expr(node.value)
                self._taint_of(node.value)

        elif isinstance(node, ast.Delete):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted.pop(target.id, None)
                else:
                    self._scan_expr(target)

        elif isinstance(node, ast.If):
            self._scan_expr(node.test)
            self._taint_of(node.test)
            self._branch([node.body, node.orelse])

        elif isinstance(node, ast.While):
            self._scan_expr(node.test)
            self._taint_of(node.test)
            self._loop(node, target=None, iter_node=None)

        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self._loop(node, target=node.target, iter_node=node.iter)

        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self._scan_expr(item.context_expr)
                info = self._taint_of(item.context_expr)
                if item.optional_vars is not None:
                    self._bind(item.optional_vars, info)
            self._visit_body(node.body)

        elif isinstance(node, ast.Try) or (
            _TRYSTAR_SUPPORTED and isinstance(node, ast.TryStar)
        ):
            self._visit_try(node)

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._visit_nested_function(node)

        elif isinstance(node, ast.ClassDef):
            for decorator in node.decorator_list:
                self._scan_expr(decorator)
            for base in node.bases:
                self._scan_expr(base)
            self._visit_body(node.body)
            self.tainted.pop(node.name, None)

        elif isinstance(node, ast.Raise):
            self._scan_expr(node.exc)
            self._scan_expr(node.cause)

        elif isinstance(node, ast.Assert):
            self._scan_expr(node.test)
            self._scan_expr(node.msg)

        elif _MATCH_SUPPORTED and isinstance(node, ast.Match):
            self._visit_match(node)

        elif isinstance(
            node,
            (
                ast.Import,
                ast.ImportFrom,
                ast.Pass,
                ast.Break,
                ast.Continue,
                ast.Global,
                ast.Nonlocal,
            ),
        ):
            pass

        else:  # pragma: no cover - future statement types
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self._scan_expr(child)

    def _visit_try(self, node) -> None:
        base = dict(self.tainted)
        self._visit_body(node.body)
        self._visit_body(node.orelse)
        after_body = dict(self.tainted)

        # An exception can fire at any point inside the body, so a handler may
        # observe either the pre-body or the post-body state.
        handler_entry = self._merge_states([base, after_body])
        handler_states: List[Dict[str, TaintInfo]] = []
        for handler in node.handlers:
            self._scan_expr(handler.type)
            self.tainted = dict(handler_entry)
            if handler.name:
                self.tainted.pop(handler.name, None)
            self._visit_body(handler.body)
            handler_states.append(self.tainted)

        self.tainted = self._merge_states([after_body] + handler_states)
        self._visit_body(node.finalbody)

    def _visit_match(self, node) -> None:
        self._scan_expr(node.subject)
        subject = self._taint_of(node.subject)
        base = dict(self.tainted)
        states: List[Dict[str, TaintInfo]] = [base]
        for case in node.cases:
            self.tainted = dict(base)
            for name in _pattern_capture_names(case.pattern):
                self._set(name, _advance(subject, name))
            if case.guard is not None:
                self._scan_expr(case.guard)
            self._visit_body(case.body)
            states.append(self.tainted)
        self.tainted = self._merge_states(states)

    def _visit_nested_function(self, node: FunctionNode) -> None:
        """Analyse a closure with the enclosing taint state as its context."""
        for decorator in node.decorator_list:
            self._scan_expr(decorator)
        for default in list(node.args.defaults) + [
            d for d in node.args.kw_defaults if d is not None
        ]:
            self._scan_expr(default)

        saved = dict(self.tainted)
        for name in param_names(node):
            self.tainted.pop(name, None)  # the parameter shadows the outer binding
        self._visit_body(node.body)
        self.tainted = saved
        self.tainted.pop(node.name, None)

    def _branch(self, bodies: Sequence[Sequence[ast.stmt]]) -> None:
        """Analyse every arm from the same entry state, then merge (union)."""
        base = dict(self.tainted)
        states: List[Dict[str, TaintInfo]] = []
        for body in bodies:
            self.tainted = dict(base)
            self._visit_body(body)
            states.append(self.tainted)
        self.tainted = self._merge_states(states)

    def _loop(self, node, target, iter_node) -> None:
        """Chase the taint fixpoint, then record findings once.

        Taint can flow backwards around a loop (``parts.append(item)``), so a
        single forward pass is not enough.  Findings are suppressed while the
        fixpoint is being chased and recorded in one final pass, which keeps
        the hit list free of duplicates.
        """
        base = dict(self.tainted)
        iter_taint = None
        if iter_node is not None:
            self._scan_expr(iter_node)
            iter_taint = self._taint_of(iter_node)

        # Save and restore rather than hard-reset: a nested loop must not
        # un-silence the enclosing loop's fixpoint passes, or every finding
        # inside it would be recorded several times over.
        was_silent = self._silent
        self._silent = True
        try:
            for _ in range(MAX_LOOP_PASSES):
                before = self._snapshot()
                if target is not None:
                    self._bind(target, iter_taint)
                self._visit_body(node.body)
                if self._snapshot() == before:
                    break
        finally:
            self._silent = was_silent

        if target is not None:
            self._bind(target, iter_taint)
        self._visit_body(node.body)

        # The loop may execute zero times, so the entry state survives.
        self.tainted = self._merge_states([self.tainted, base])
        self._visit_body(node.orelse)

    def _record_const_bool(self, node: ast.Assign) -> None:
        """Track ``flag = True`` so ``shell=flag`` can be resolved."""
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            return
        name = node.targets[0].id
        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, bool):
            self.const_bools[name] = value.value
        else:
            self.const_bools.pop(name, None)

    # -- assignment targets ------------------------------------------------

    def _scan_target(self, target: ast.expr) -> None:
        """Sinks can hide in a target's subscript, e.g. ``d[eval(x)] = 1``."""
        if isinstance(target, ast.Subscript):
            self._scan_expr(target.slice)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._scan_target(elt)

    def _bind(self, target: ast.expr, info: Optional[TaintInfo]) -> None:
        if isinstance(target, ast.Name):
            # Reassignment to a clean value CLEARS the taint.  Getting this
            # wrong is the single biggest false-positive risk in the engine.
            self._set(target.id, _advance(info, target.id))
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._bind(elt, info)  # conservative: taint every target
        elif isinstance(target, ast.Starred):
            self._bind(target.value, info)
        elif isinstance(target, (ast.Subscript, ast.Attribute)):
            # ``lst[0] = tainted`` taints the whole container.  Assigning a
            # clean value to one slot does NOT clear it - we have no element
            # level alias analysis, so clearing would be unsound.
            if info is None:
                return
            base = _base_name(target)
            if base is not None:
                self._set(base, _advance(info, base))

    # -- expressions: side effects (sinks + receiver mutation) -------------

    def _scan_expr(self, node: Optional[ast.AST], depth: int = 0) -> None:
        if node is None or depth > MAX_EXPR_DEPTH:
            return
        if isinstance(node, ast.Call):
            self._check_call(node)
            self._apply_mutation(node)
        for child in ast.iter_child_nodes(node):
            self._scan_expr(child, depth + 1)

    def _apply_mutation(self, node: ast.Call) -> None:
        """``parts.append(tainted)`` taints ``parts``."""
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr not in MUTATING_METHODS:
            return
        base = _base_name(func.value)
        if base is None:
            return
        info = _merge_all(
            [self._taint_of(arg) for arg in node.args]
            + [self._taint_of(kw.value) for kw in node.keywords]
        )
        if info is not None:
            self._set(base, _advance(info, base))

    # -- expressions: taint value ------------------------------------------

    def _taint_of(self, node: Optional[ast.AST], depth: int = 0) -> Optional[TaintInfo]:
        if node is None or depth > MAX_EXPR_DEPTH:
            return None
        d = depth + 1

        if isinstance(node, ast.Name):
            return self.tainted.get(node.id)

        if isinstance(node, ast.Constant):
            return None

        if isinstance(node, ast.JoinedStr):
            info = _merge_all(self._taint_of(v, d) for v in node.values)
            if info is not None:
                self.has_fstring_flow = True
            return info

        if isinstance(node, ast.FormattedValue):
            return _merge(
                self._taint_of(node.value, d), self._taint_of(node.format_spec, d)
            )

        if isinstance(node, ast.BinOp):
            info = _merge(self._taint_of(node.left, d), self._taint_of(node.right, d))
            if info is not None and isinstance(node.op, ast.Add):
                self.has_concat_flow = True
            return info

        if isinstance(node, ast.UnaryOp):
            return self._taint_of(node.operand, d)

        if isinstance(node, ast.BoolOp):
            return _merge_all(self._taint_of(v, d) for v in node.values)

        if isinstance(node, ast.Compare):
            return None  # a comparison yields a bool, not attacker data

        if isinstance(node, ast.IfExp):
            return _merge(self._taint_of(node.body, d), self._taint_of(node.orelse, d))

        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return _merge_all(self._taint_of(e, d) for e in node.elts)

        if isinstance(node, ast.Dict):
            return _merge_all(
                [self._taint_of(k, d) for k in node.keys]
                + [self._taint_of(v, d) for v in node.values]
            )

        if isinstance(node, ast.Starred):
            return self._taint_of(node.value, d)

        if isinstance(node, ast.Await):
            return self._taint_of(node.value, d)

        if isinstance(node, ast.NamedExpr):  # walrus
            info = self._taint_of(node.value, d)
            self._bind(node.target, info)
            return info

        if isinstance(node, ast.Attribute):
            dotted = self._resolve(node)
            if dotted in UNTRUSTED_ATTRIBUTE_SOURCES:
                return _untrusted()
            return self._taint_of(node.value, d)

        if isinstance(node, ast.Subscript):
            # Taint follows the BASE, not the index.  ``TABLE[user_choice]``
            # returns a value from a trusted table, so it stays clean; that is
            # what keeps allowlist-validated tools out of the findings.
            base_dotted = self._resolve(node.value)
            if base_dotted in UNTRUSTED_ATTRIBUTE_SOURCES:
                return _untrusted()
            return self._taint_of(node.value, d)

        if isinstance(node, ast.Slice):
            return _merge_all(
                [
                    self._taint_of(node.lower, d),
                    self._taint_of(node.upper, d),
                    self._taint_of(node.step, d),
                ]
            )

        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            parts = [self._taint_of(node.elt, d)]
            parts.extend(self._comprehension_taint(node.generators, d))
            return _merge_all(parts)

        if isinstance(node, ast.DictComp):
            parts = [self._taint_of(node.key, d), self._taint_of(node.value, d)]
            parts.extend(self._comprehension_taint(node.generators, d))
            return _merge_all(parts)

        if isinstance(node, ast.Lambda):
            return None

        if isinstance(node, ast.Call):
            return self._taint_of_call(node, d)

        return None

    def _comprehension_taint(
        self, generators: Sequence[ast.comprehension], depth: int
    ) -> List[Optional[TaintInfo]]:
        parts: List[Optional[TaintInfo]] = []
        for gen in generators:
            parts.append(self._taint_of(gen.iter, depth))
            for cond in gen.ifs:
                parts.append(self._taint_of(cond, depth))
        return parts

    def _taint_of_call(self, node: ast.Call, depth: int) -> Optional[TaintInfo]:
        dotted = self._resolve(node.func)
        arg_taint = _merge_all(
            [self._taint_of(a, depth) for a in node.args]
            + [self._taint_of(kw.value, depth) for kw in node.keywords]
        )

        if dotted is not None:
            if dotted in SANITIZERS:
                if arg_taint is None:
                    return None
                return replace(arg_taint, sanitized=True)
            if dotted in DIRECT_UNTRUSTED_CALLS:
                return _untrusted()
            if dotted in CONDITIONAL_UNTRUSTED_CALLS:
                return arg_taint
            if dotted in PROPAGATING_CALLS:
                return arg_taint
            if dotted in SINKS:
                # The result of a tainted dangerous call is itself tainted.
                return arg_taint

        if isinstance(node.func, ast.Attribute):
            base_taint = self._taint_of(node.func.value, depth)
            attr = node.func.attr
            if attr in STRING_TRANSFORM_METHODS:
                return _merge(base_taint, arg_taint)
            return base_taint

        # An unknown free function: no inter-procedural analysis, so its
        # return value is treated as clean.  See README limitations.
        return None

    # -- sink detection ----------------------------------------------------

    def _check_call(self, node: ast.Call) -> None:
        dotted = self._resolve(node.func)
        if dotted is None:
            return
        spec = SINKS.get(dotted)
        if spec is None:
            return
        category, positions, kwarg_names, conditional = spec

        if conditional == "shell_true":
            if not self._uses_shell(node):
                return  # argv list form - not a shell injection sink
            self.shell_true_present = True
        elif conditional == "no_safe_loader":
            if self._has_safe_loader(node):
                return

        candidates: List[Tuple[Optional[int], Optional[str], ast.expr]] = []
        for index in positions:
            if index >= len(node.args):
                continue
            if any(isinstance(a, ast.Starred) for a in node.args[: index + 1]):
                continue  # *args shifts the positions; cannot match reliably
            candidates.append((index, None, node.args[index]))
        for keyword in node.keywords:
            if keyword.arg is not None and keyword.arg in kwarg_names:
                candidates.append((None, keyword.arg, keyword.value))

        for index, kwarg, expr in candidates:
            info = self._taint_of(expr)
            if info is None:
                continue
            hops = info.hops + 1
            self._record(
                SinkHit(
                    sink_name=dotted,
                    category=category,
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    tainted_arg_index=index,
                    tainted_arg_name=kwarg,
                    n_hops=hops,
                    source_param=info.origin,
                    path=info.path,
                    sanitized=info.sanitized,
                    severity=_severity(category, hops, info.sanitized),
                    code_excerpt=self._line(node.lineno),
                )
            )

    def _record(self, hit: SinkHit) -> None:
        if not self._silent:
            self.hits.append(hit)

    def _uses_shell(self, node: ast.Call) -> bool:
        for keyword in node.keywords:
            if keyword.arg == "shell":
                value = keyword.value
                if isinstance(value, ast.Constant):
                    return bool(value.value)
                if isinstance(value, ast.Name) and value.id in self.const_bools:
                    return self.const_bools[value.id]
                return True  # unknown expression - assume the worst
            if keyword.arg is None:
                return True  # **kwargs could carry shell=True
        return False

    def _has_safe_loader(self, node: ast.Call) -> bool:
        loader: Optional[ast.expr] = None
        if len(node.args) > 1:
            loader = node.args[1]
        for keyword in node.keywords:
            if keyword.arg == "Loader":
                loader = keyword.value
        if loader is None:
            return False
        dotted = self._resolve(loader)
        if dotted is None:
            return False
        return dotted.rsplit(".", 1)[-1] in SAFE_YAML_LOADERS

    # -- helpers -----------------------------------------------------------

    def _resolve(self, node: Optional[ast.AST]) -> Optional[str]:
        """Dotted name for a Name/Attribute chain, with aliases applied."""
        parts: List[str] = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if not isinstance(current, ast.Name):
            return None
        parts.append(current.id)
        parts.reverse()
        head = parts[0]
        if head in self.aliases:
            parts = self.aliases[head].split(".") + parts[1:]
        return ".".join(parts)

    def _line(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""

    def flow_facts(self) -> FlowFacts:
        return FlowFacts(
            n_tainted_vars=len(self.ever_tainted),
            has_fstring_flow=self.has_fstring_flow,
            has_concat_flow=self.has_concat_flow,
            shell_true_present=self.shell_true_present,
        )


def _base_name(node: ast.AST) -> Optional[str]:
    """The leftmost ``Name`` of an attribute/subscript chain."""
    current = node
    while isinstance(current, (ast.Attribute, ast.Subscript)):
        current = current.value
    if isinstance(current, ast.Name):
        return current.id
    return None


def _pattern_capture_names(pattern: ast.AST) -> List[str]:
    """Names bound by a ``match`` pattern, in deterministic order."""
    names: List[str] = []
    for node in ast.walk(pattern):
        name = getattr(node, "name", None)
        if isinstance(name, str):
            names.append(name)
        rest = getattr(node, "rest", None)
        if isinstance(rest, str):
            names.append(rest)
    return sorted(set(names))


def _dedupe_hits(hits: Sequence[SinkHit]) -> Tuple[SinkHit, ...]:
    """One finding per (call site, tainted argument), keeping the worst."""
    best: Dict[Tuple, SinkHit] = {}
    for hit in hits:
        key = (
            hit.lineno,
            hit.col_offset,
            hit.sink_name,
            hit.tainted_arg_index,
            hit.tainted_arg_name,
        )
        current = best.get(key)
        if current is None or _hit_rank(hit) > _hit_rank(current):
            best[key] = hit
    return tuple(sorted(best.values(), key=lambda h: h.sort_key))


def _hit_rank(hit: SinkHit) -> Tuple[int, int, int]:
    return (SEVERITY_RANK[hit.severity], 0 if hit.sanitized else 1, -hit.n_hops)


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def _analyze_function(
    fn: FunctionNode, lines: Sequence[str], aliases: Dict[str, str]
) -> ToolAnalysis:
    docstring = extract_docstring(fn)
    try:
        engine = _FunctionAnalyzer(fn, lines, aliases)
        engine.run()
    except RecursionError as exc:  # pragma: no cover - depth guard normally wins
        return ToolAnalysis(
            tool_name=fn.name,
            lineno=fn.lineno,
            params=tuple(param_names(fn)),
            reaches_sink=False,
            hits=(),
            max_severity=Severity.NONE,
            n_hops_min=None,
            sink_categories=(),
            parse_ok=False,
            error="recursion limit exceeded: {}".format(exc),
            docstring=docstring,
        )
    except Exception as exc:  # fail-safe: never crash on hostile input
        return ToolAnalysis(
            tool_name=fn.name,
            lineno=fn.lineno,
            params=tuple(param_names(fn)),
            reaches_sink=False,
            hits=(),
            max_severity=Severity.NONE,
            n_hops_min=None,
            sink_categories=(),
            parse_ok=False,
            error="{}: {}".format(type(exc).__name__, exc),
            docstring=docstring,
        )

    hits = _dedupe_hits(engine.hits)
    return ToolAnalysis(
        tool_name=fn.name,
        lineno=fn.lineno,
        params=tuple(engine.params),
        reaches_sink=bool(hits),
        hits=hits,
        max_severity=max_severity(h.severity for h in hits),
        n_hops_min=min((h.n_hops for h in hits), default=None),
        sink_categories=sort_categories(h.category for h in hits),
        parse_ok=True,
        error=None,
        docstring=docstring,
        flow_facts=engine.flow_facts(),
    )


def analyze_source(
    source: str, file_path: str = "<string>", all_functions: bool = False
) -> FileAnalysis:
    """Analyse a source string.  Pure function, no global state."""
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    try:
        tree = parse_module(source, file_path)
    except ParseError as exc:
        return FileAnalysis(
            file_path=file_path,
            content_sha256=digest,
            tools=(),
            parse_ok=False,
            error=str(exc),
        )

    aliases = build_alias_map(tree)
    lines = source.splitlines()
    tools = [
        _analyze_function(fn, lines, aliases)
        for fn in collect_tool_functions(tree, all_functions=all_functions)
    ]
    tools.sort(key=lambda t: (t.lineno, t.tool_name))
    return FileAnalysis(
        file_path=file_path,
        content_sha256=digest,
        tools=tuple(tools),
        parse_ok=True,
        error=None,
    )


def read_source(path: Union[str, Path]) -> str:
    """Decode a ``.py`` file, honouring a PEP 263 coding cookie.

    Falls back to UTF-8 and then Latin-1 so a file with stray non-UTF-8
    bytes is analysed rather than skipped.
    """
    raw = Path(path).read_bytes()
    encoding = "utf-8"
    try:
        encoding = tokenize.detect_encoding(io.BytesIO(raw).readline)[0]
    except (SyntaxError, UnicodeDecodeError):
        encoding = "utf-8"
    for candidate in (encoding, "utf-8", "latin-1"):
        try:
            return raw.decode(candidate)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1", errors="replace")  # pragma: no cover


def analyze_file(
    path: Union[str, Path], all_functions: bool = False
) -> FileAnalysis:
    """Analyse one ``.py`` file.  Unreadable files return a structured error."""
    posix = Path(path).as_posix()
    try:
        source = read_source(path)
    except OSError as exc:
        return FileAnalysis(
            file_path=posix,
            content_sha256="",
            tools=(),
            parse_ok=False,
            error="{}: {}".format(type(exc).__name__, exc),
        )
    return analyze_source(source, file_path=posix, all_functions=all_functions)


def analyze_repo(
    root: Union[str, Path], all_functions: bool = False
) -> List[FileAnalysis]:
    """Walk a directory for ``.py`` files, sorted for reproducible output.

    Skips ``venv/``, ``.git/``, ``__pycache__/``, ``tests/``,
    ``site-packages/`` and friends (see ``SKIP_DIR_NAMES``).  The root
    directory itself is never skipped, so pointing the analyzer straight at
    a ``tests/`` folder still works.
    """
    root_path = Path(root)
    if root_path.is_file():
        return [analyze_file(root_path, all_functions=all_functions)]

    collected: List[Tuple[str, Path]] = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIR_NAMES)
        for filename in sorted(filenames):
            if not filename.endswith(".py"):
                continue
            full = Path(dirpath) / filename
            rel = full.relative_to(root_path).as_posix()
            collected.append((rel, full))

    collected.sort(key=lambda item: item[0])
    results: List[FileAnalysis] = []
    for rel, full in collected:
        analysis = analyze_file(full, all_functions=all_functions)
        results.append(replace(analysis, file_path=rel))
    return results
