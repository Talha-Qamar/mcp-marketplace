"""MCP Secure - Part 2: deterministic AST taint analyzer.

Static command-injection detection for MCP server tool functions.  Parses
Python source, tracks which variables carry attacker-controlled data, and
reports whether that data reaches a dangerous execution sink.

Two consumers, two outputs:

* the deterministic policy engine reads the hard verdict and its evidence
  (:class:`~ast_taint.models.SinkHit`);
* Model B reads the fixed-length numeric vector
  (:func:`~ast_taint.features.to_feature_vector`).

The analysed code is never imported, compiled or executed.
"""

from __future__ import annotations

from .analyzer import analyze_file, analyze_repo, analyze_source, read_source
from .exceptions import AnalysisError, AstTaintError, ParseError
from .extractor import extract_docstring, extract_tools
from .features import (
    FEATURE_CAPS,
    FEATURE_NAMES,
    FEATURE_VERSION,
    label_hint,
    to_feature_dict,
    to_feature_vector,
)
from .models import (
    FileAnalysis,
    FlowFacts,
    Severity,
    SinkCategory,
    SinkHit,
    ToolAnalysis,
)

__version__ = "0.1.0"

__all__ = [
    "AnalysisError",
    "AstTaintError",
    "FEATURE_CAPS",
    "FEATURE_NAMES",
    "FEATURE_VERSION",
    "FileAnalysis",
    "FlowFacts",
    "ParseError",
    "Severity",
    "SinkCategory",
    "SinkHit",
    "ToolAnalysis",
    "__version__",
    "analyze_file",
    "analyze_repo",
    "analyze_source",
    "extract_docstring",
    "extract_tools",
    "label_hint",
    "read_source",
    "to_feature_dict",
    "to_feature_vector",
]
