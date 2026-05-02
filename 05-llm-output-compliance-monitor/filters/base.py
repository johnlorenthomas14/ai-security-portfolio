"""Filter protocol, Finding/Decision dataclasses, and the Action enum.

Each filter implements ``OutputFilter.scan(text) -> list[Finding]``. The
OutputMonitor combines findings into a final Decision based on the
strongest action requested by any finding:

  - block   — refuse to return the response at all (highest precedence)
  - redact  — replace matched substrings with a redaction placeholder
  - flag    — log the finding but pass the response through unchanged
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol


class Action(str, Enum):
    """The action a finding requests of the OutputMonitor."""

    BLOCK = "block"     # never return this response to the user
    REDACT = "redact"   # replace the matched span with a placeholder
    FLAG = "flag"       # log only — pass through unchanged

    @property
    def precedence(self) -> int:
        return {"block": 3, "redact": 2, "flag": 1}.get(self.value, 0)


@dataclass
class Finding:
    """One filter finding against one response."""

    finding_id: str
    filter_name: str
    category: str
    action: Action
    severity: str         # low | medium | high | critical
    title: str
    matched_span: tuple[int, int]   # (start, end) char offsets in the response
    matched_text: str               # the text that matched
    redaction_text: str = "[REDACTED]"
    rationale: str = ""
    owasp_category: str = ""
    atlas_techniques: list[str] = field(default_factory=list)
    airmf_subcategory: str = ""


@dataclass
class Decision:
    """Final monitor decision for one response."""

    verdict: str          # "pass" | "redact" | "block"
    response_in: str      # original response text
    response_out: str     # what to return to the user (may be redacted or blocked)
    findings: list[Finding]
    audit_entry_id: str = ""

    @property
    def blocked(self) -> bool:
        return self.verdict == "block"

    @property
    def redacted(self) -> bool:
        return self.verdict == "redact"


class OutputFilter(Protocol):
    """Each filter scans one response and returns findings for matched content."""

    name: str
    category: str

    def scan(self, text: str) -> list[Finding]:
        """Return findings for `text`. Empty list = clean."""
        ...
