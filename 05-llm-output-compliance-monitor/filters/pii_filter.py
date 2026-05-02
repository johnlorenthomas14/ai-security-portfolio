"""PIIFilter — detects personally identifiable information in LLM output.

Action: REDACT for matched spans. PII in an LLM response is a leak the
user shouldn't see, but unlike a secret, the response is usually still
useful with the PII redacted. Critical PII categories (SSN, credit card)
get redacted with a category label so the user knows what was removed.
"""

from __future__ import annotations

import re

from .base import Action, Finding


_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}(?!\d)"
)
_CC_RE = re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)")


class PIIFilter:
    name = "pii_filter"
    category = "pii_disclosure"

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _EMAIL_RE.finditer(text):
            findings.append(_make(text, match, "email", "medium",
                                  "Email address in LLM output", "[REDACTED:EMAIL]"))
        for match in _SSN_RE.finditer(text):
            findings.append(_make(text, match, "ssn", "high",
                                  "US Social Security Number in LLM output", "[REDACTED:SSN]"))
        for match in _PHONE_RE.finditer(text):
            findings.append(_make(text, match, "phone", "low",
                                  "US phone number in LLM output", "[REDACTED:PHONE]"))
        for match in _CC_RE.finditer(text):
            digits = re.sub(r"\D", "", match.group(0))
            if 13 <= len(digits) <= 19 and _luhn_valid(digits):
                findings.append(_make(text, match, "credit_card", "high",
                                      "Credit card number in LLM output",
                                      "[REDACTED:CREDIT_CARD]"))
        return findings


def _make(
    text: str, match: re.Match, kind: str, severity: str, title: str,
    redaction: str,
) -> Finding:
    return Finding(
        finding_id=f"OUT-PII-{kind}-{match.start()}",
        filter_name=PIIFilter.name,
        category="pii_disclosure",
        action=Action.REDACT,
        severity=severity,
        title=title,
        matched_span=(match.start(), match.end()),
        matched_text=match.group(0),
        redaction_text=redaction,
        rationale=(
            f"LLM-generated response contains {kind}. Redacted before "
            "returning to user; original logged to the hash-chained audit "
            "log per FedRAMP-style integrity requirements."
        ),
        owasp_category="LLM02",
        atlas_techniques=["AML.T0024"],
        airmf_subcategory="MEASURE 2.10",
    )


def _luhn_valid(digits: str) -> bool:
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
