"""Immutable result objects produced by the taint engine.

Determinism rule
----------------
Every collection on these objects is a ``tuple``, and every list built
internally is sorted by a stable key (lineno, col_offset, sink_name, ...)
before it is frozen into one.  No timestamps, no object ids, no hash-order
dependence: the same source string always produces byte-identical JSON.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class Severity(str, Enum):
    """How bad a single finding is."""

    NONE = "none"
    LOW = "low"  # tainted data reaches a sink, but a sanitizer was seen on the path
    MEDIUM = "medium"  # indirect flow (>2 hops) or dynamic/file/deserialize sink
    HIGH = "high"  # direct tainted flow into a shell/exec sink


class SinkCategory(str, Enum):
    """What kind of dangerous operation the tainted value reached."""

    SHELL = "shell"  # os.system, subprocess with shell=True
    EXEC = "exec"  # eval, exec, compile
    DYNAMIC = "dynamic"  # getattr, __import__, importlib
    FILE = "file"  # open() with a tainted path
    DESERIALIZE = "deserialize"  # pickle.loads, unsafe yaml.load


#: Numeric rank used for ``max_severity`` comparison and feature encoding.
SEVERITY_RANK: Dict[Severity, int] = {
    Severity.NONE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}

#: Fixed order used whenever sink categories are serialised.
CATEGORY_ORDER: Tuple[SinkCategory, ...] = (
    SinkCategory.SHELL,
    SinkCategory.EXEC,
    SinkCategory.DYNAMIC,
    SinkCategory.FILE,
    SinkCategory.DESERIALIZE,
)


@dataclass(frozen=True)
class SinkHit:
    """One tainted value arriving at one dangerous argument of one call."""

    sink_name: str  # e.g. "os.system" (after alias resolution)
    category: SinkCategory
    lineno: int
    col_offset: int
    tainted_arg_index: Optional[int]  # positional index, None when it was a kwarg
    tainted_arg_name: Optional[str]  # kwarg name, None when it was positional
    n_hops: int  # assignments between the source and this sink (>= 1)
    source_param: str  # the tool parameter the taint originated from
    path: Tuple[str, ...]  # variable names along the flow, e.g. ("q", "cmd")
    sanitized: bool  # a known sanitizer appeared on the path
    severity: Severity
    code_excerpt: str  # the source line, stripped

    @property
    def sort_key(self) -> Tuple[int, int, str, int, str]:
        return (
            self.lineno,
            self.col_offset,
            self.sink_name,
            -1 if self.tainted_arg_index is None else self.tainted_arg_index,
            self.tainted_arg_name or "",
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "code_excerpt": self.code_excerpt,
            "col_offset": self.col_offset,
            "lineno": self.lineno,
            "n_hops": self.n_hops,
            "path": list(self.path),
            "sanitized": self.sanitized,
            "severity": self.severity.value,
            "sink_name": self.sink_name,
            "source_param": self.source_param,
            "tainted_arg_index": self.tainted_arg_index,
            "tainted_arg_name": self.tainted_arg_name,
        }

    def render_flow(self, arrow: str = "->") -> str:
        """``q -> cmd -> os.system()`` - the human-readable taint path."""
        steps = list(self.path) + ["{}()".format(self.sink_name)]
        return (" " + arrow + " ").join(steps)


@dataclass(frozen=True)
class FlowFacts:
    """Per-tool facts that are not derivable from ``hits`` alone.

    These exist because the frozen Model B feature vector needs them
    (``n_tainted_vars``, ``has_fstring_flow``, ``has_concat_flow``,
    ``shell_true_present``).  They are observations about the whole
    function body, not about any single finding.
    """

    n_tainted_vars: int = 0
    has_fstring_flow: bool = False
    has_concat_flow: bool = False
    shell_true_present: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "has_concat_flow": self.has_concat_flow,
            "has_fstring_flow": self.has_fstring_flow,
            "n_tainted_vars": self.n_tainted_vars,
            "shell_true_present": self.shell_true_present,
        }


EMPTY_FLOW_FACTS = FlowFacts()


@dataclass(frozen=True)
class ToolAnalysis:
    """The verdict for a single tool function."""

    tool_name: str
    lineno: int
    params: Tuple[str, ...]
    reaches_sink: bool
    hits: Tuple[SinkHit, ...]
    max_severity: Severity
    n_hops_min: Optional[int]  # shortest path to any sink, None when clean
    sink_categories: Tuple[SinkCategory, ...]  # sorted, deduped
    parse_ok: bool
    error: Optional[str] = None
    docstring: Optional[str] = None  # the tool description - Model A consumes this
    flow_facts: FlowFacts = EMPTY_FLOW_FACTS

    def to_dict(self, include_docstring: bool = True) -> Dict[str, Any]:
        # Keys are inserted in sorted order so a plain dump and a
        # sort_keys=True dump are byte-identical.
        out: Dict[str, Any] = {}
        if include_docstring:
            out["docstring"] = self.docstring
        out["error"] = self.error
        out["flow_facts"] = self.flow_facts.to_dict()
        out["hits"] = [hit.to_dict() for hit in self.hits]
        out["lineno"] = self.lineno
        out["max_severity"] = self.max_severity.value
        out["n_hops_min"] = self.n_hops_min
        out["params"] = list(self.params)
        out["parse_ok"] = self.parse_ok
        out["reaches_sink"] = self.reaches_sink
        out["sink_categories"] = [c.value for c in self.sink_categories]
        out["tool_name"] = self.tool_name
        return out


@dataclass(frozen=True)
class FileAnalysis:
    """The verdict for a single ``.py`` file."""

    file_path: str
    content_sha256: str
    tools: Tuple[ToolAnalysis, ...]
    parse_ok: bool
    error: Optional[str] = None

    @property
    def max_severity(self) -> Severity:
        best = Severity.NONE
        for tool in self.tools:
            if SEVERITY_RANK[tool.max_severity] > SEVERITY_RANK[best]:
                best = tool.max_severity
        return best

    @property
    def all_hits(self) -> Tuple[SinkHit, ...]:
        hits: List[SinkHit] = []
        for tool in self.tools:
            hits.extend(tool.hits)
        return tuple(hits)

    def to_dict(self, include_docstring: bool = True) -> Dict[str, Any]:
        return {
            "content_sha256": self.content_sha256,
            "error": self.error,
            "file_path": self.file_path,
            "parse_ok": self.parse_ok,
            "tools": [t.to_dict(include_docstring) for t in self.tools],
        }


def sort_categories(categories) -> Tuple[SinkCategory, ...]:
    """Dedupe and order categories by the fixed ``CATEGORY_ORDER``."""
    seen = set(categories)
    return tuple(c for c in CATEGORY_ORDER if c in seen)


def max_severity(severities) -> Severity:
    """Highest severity in an iterable, ``Severity.NONE`` when empty."""
    best = Severity.NONE
    for sev in severities:
        if SEVERITY_RANK[sev] > SEVERITY_RANK[best]:
            best = sev
    return best
