"""Scanner base types — Document, Finding, and the DocumentScanner protocol."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


@dataclass
class Document:
    """One document loaded from a corpus directory."""

    path: Path
    text: str
    relative_path: str  # path relative to the corpus root, for reporting


@dataclass
class Finding:
    """One scanner finding against one document.

    Severity is `low | medium | high | critical`.
    OWASP/ATLAS/AI RMF tags carry through the entire pipeline so the
    audit report can be sliced by any of them.
    """

    finding_id: str
    document_path: str
    scanner: str
    category: str
    severity: str
    title: str
    excerpt: str
    line_number: int | None = None
    owasp_category: str = ""
    atlas_techniques: list[str] = field(default_factory=list)
    airmf_subcategory: str = ""
    rationale: str = ""


class DocumentScanner(Protocol):
    """Minimal interface the auditor needs from any scanner."""

    name: str
    category: str

    def scan(self, document: Document) -> list[Finding]:
        """Return findings for `document`. Empty list = clean."""
        ...
