"""PIIScanner — detects personally identifiable information in corpus documents.

Catches the most common PII categories with deterministic regex patterns:
  - Email addresses
  - US Social Security Numbers (SSN)
  - US phone numbers
  - Credit card numbers (Luhn-validated to suppress false positives)

Deliberate scope cuts: name detection (requires NER, fragile, false-positive
heavy) and address detection (also NER-shaped) are roadmap items for a
spaCy/presidio integration. Regex on structured PII is high-precision and
the right MVP.
"""

from __future__ import annotations

import re

from .base import Document, Finding


# Email — RFC-5322-lite. Strict enough to avoid matching every word with
# an @ in it but liberal enough to catch realistic addresses.
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# SSN — three digits, dash, two digits, dash, four digits, with negative
# lookbehind/ahead so it doesn't match inside longer digit runs.
_SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")

# US phone — handles 555-555-5555, (555) 555-5555, 555.555.5555, +1-555-...
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}(?!\d)"
)

# Credit card — 13 to 19 digits, optionally separated by dashes/spaces.
# Luhn-validated below to suppress false positives.
_CC_RE = re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)")


class PIIScanner:
    """Regex-based scanner for structured PII categories."""

    name = "pii_scanner"
    category = "pii_disclosure"

    def scan(self, document: Document) -> list[Finding]:
        findings: list[Finding] = []
        for line_idx, line in enumerate(document.text.splitlines(), start=1):
            for match in _EMAIL_RE.finditer(line):
                findings.append(
                    self._make(document, line_idx, line, match.group(0), "email", "medium")
                )
            for match in _SSN_RE.finditer(line):
                findings.append(
                    self._make(document, line_idx, line, match.group(0), "ssn", "high")
                )
            for match in _PHONE_RE.finditer(line):
                findings.append(
                    self._make(document, line_idx, line, match.group(0), "phone", "low")
                )
            for match in _CC_RE.finditer(line):
                digits = re.sub(r"\D", "", match.group(0))
                if 13 <= len(digits) <= 19 and _luhn_valid(digits):
                    findings.append(
                        self._make(
                            document, line_idx, line, match.group(0), "credit_card", "high"
                        )
                    )
        return findings

    def _make(
        self,
        document: Document,
        line_number: int,
        line: str,
        matched: str,
        kind: str,
        severity: str,
    ) -> Finding:
        return Finding(
            finding_id=f"RAG-PII-{kind}-{document.relative_path}-L{line_number}",
            document_path=document.relative_path,
            scanner=self.name,
            category=self.category,
            severity=severity,
            title=f"PII detected in corpus document — {kind}",
            excerpt=line.strip()[:480],
            line_number=line_number,
            owasp_category="LLM02",
            atlas_techniques=["AML.T0024"],
            airmf_subcategory="MEASURE 2.10",
            rationale=(
                f"Document contains {kind} ({matched!r}). Once this document is "
                "retrieved as RAG context, the LLM may reproduce this PII in "
                "responses to user queries — including unauthorized users. "
                "Recommend redaction at corpus-ingestion time."
            ),
        )


def _luhn_valid(digits: str) -> bool:
    """Validate a digit-only string with Luhn's algorithm."""
    total = 0
    parity = len(digits) % 2
    for idx, ch in enumerate(digits):
        d = int(ch)
        if idx % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0
