"""Exception hierarchy for the AST taint analyzer.

Nothing in this package ever raises out of the public API for *content*
reasons: a file that cannot be parsed comes back as a structured
``FileAnalysis`` with ``parse_ok=False``.  These exceptions exist for the
lower-level helpers (and for callers who want the strict behaviour).
"""

from __future__ import annotations

from typing import Optional


class AstTaintError(Exception):
    """Base class for every error raised by this package."""


class ParseError(AstTaintError):
    """Raised when a source string is not valid Python."""

    def __init__(
        self,
        message: str,
        lineno: Optional[int] = None,
        col_offset: Optional[int] = None,
        file_path: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.lineno = lineno
        self.col_offset = col_offset
        self.file_path = file_path

    def __str__(self) -> str:  # pragma: no cover - trivial formatting
        where = self.file_path or "<string>"
        if self.lineno is not None:
            return f"{where}:{self.lineno}:{self.col_offset or 0}: {self.message}"
        return f"{where}: {self.message}"


class AnalysisError(AstTaintError):
    """Raised when the taint engine fails on an otherwise parseable file."""
