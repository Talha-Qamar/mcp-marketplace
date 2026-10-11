"""The Part 2 -> Part 3 contract: a fixed-length numeric view of a tool.

Model B (GraphCodeBERT) concatenates this vector into its classification
head.  **FROZEN**: the names, their order and their ranges must never
change once Model B has been trained, or its learned weights stop meaning
anything.  Adding a feature means retraining Model B.
"""

from __future__ import annotations

from typing import Dict, List

from .models import SEVERITY_RANK, SinkCategory, ToolAnalysis

#: Fixed order.  Index i of the vector is always FEATURE_NAMES[i].
FEATURE_NAMES = (
    "reaches_sink",  # 0/1
    "n_hits",  # count, capped at 10
    "min_hops",  # shortest path length, 0 if none, capped at 10
    "max_severity",  # 0=none 1=low 2=medium 3=high
    "has_shell_sink",  # 0/1
    "has_exec_sink",  # 0/1
    "has_dynamic_sink",  # 0/1
    "has_file_sink",  # 0/1
    "has_deserialize_sink",  # 0/1
    "any_sanitized",  # 0/1
    "all_sanitized",  # 0/1
    "n_params",  # capped at 10
    "n_tainted_vars",  # capped at 20
    "has_fstring_flow",  # 0/1 - taint passed through an f-string
    "has_concat_flow",  # 0/1 - taint passed through + concatenation
    "shell_true_present",  # 0/1 - a subprocess call had shell=True at all
)

#: Inclusive upper bound applied to each count feature before emission.
FEATURE_CAPS: Dict[str, int] = {
    "n_hits": 10,
    "min_hops": 10,
    "max_severity": 3,
    "n_params": 10,
    "n_tainted_vars": 20,
}

FEATURE_VERSION = "1.0.0"


def _cap(value: int, limit: int) -> float:
    return float(min(value, limit))


def to_feature_vector(tool: ToolAnalysis) -> List[float]:
    """``len(FEATURE_NAMES)`` floats, in ``FEATURE_NAMES`` order, every time.

    Values are left raw (only capped).  Scaling belongs in the model's
    preprocessing, not in the analyzer.
    """
    hits = tool.hits
    categories = set(tool.sink_categories)
    sanitized_flags = [hit.sanitized for hit in hits]
    facts = tool.flow_facts

    return [
        1.0 if tool.reaches_sink else 0.0,
        _cap(len(hits), FEATURE_CAPS["n_hits"]),
        _cap(tool.n_hops_min or 0, FEATURE_CAPS["min_hops"]),
        float(SEVERITY_RANK[tool.max_severity]),
        1.0 if SinkCategory.SHELL in categories else 0.0,
        1.0 if SinkCategory.EXEC in categories else 0.0,
        1.0 if SinkCategory.DYNAMIC in categories else 0.0,
        1.0 if SinkCategory.FILE in categories else 0.0,
        1.0 if SinkCategory.DESERIALIZE in categories else 0.0,
        1.0 if any(sanitized_flags) else 0.0,
        1.0 if (sanitized_flags and all(sanitized_flags)) else 0.0,
        _cap(len(tool.params), FEATURE_CAPS["n_params"]),
        _cap(facts.n_tainted_vars, FEATURE_CAPS["n_tainted_vars"]),
        1.0 if facts.has_fstring_flow else 0.0,
        1.0 if facts.has_concat_flow else 0.0,
        1.0 if facts.shell_true_present else 0.0,
    ]


def to_feature_dict(tool: ToolAnalysis) -> Dict[str, float]:
    """The same values keyed by name - for debugging and data cards."""
    return dict(zip(FEATURE_NAMES, to_feature_vector(tool)))


def label_hint(tool: ToolAnalysis) -> str:
    """A CANDIDATE label, never ground truth.

    Derived mechanically from ``reaches_sink``.  Training Model B on these
    directly would be circular labelling - the whole reason Model C exists
    is to audit candidate labels against separately sourced evidence before
    they are promoted to ground truth.
    """
    return "injection" if tool.reaches_sink else "benign"
