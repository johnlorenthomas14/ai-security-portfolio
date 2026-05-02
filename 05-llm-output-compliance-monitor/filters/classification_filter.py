"""ClassificationFilter — detects classification / handling markers in LLM output.

Action: BLOCK on any match. An LLM producing CUI / CONFIDENTIAL / SECRET /
TOP SECRET / ITAR / PHI markers in its output is one of:
  - Reproducing a classified-source document it shouldn't have access to.
  - Hallucinating a classification marker (still a policy violation —
    fictional CUI is treated like real CUI in audited environments).
  - Replaying a system-prompt or context that itself contained the marker.

In any of those scenarios, the right response is to block the output,
log the finding, and let the host application escalate to the security
team. Redaction is not appropriate — the very fact that the output
contains a marker is signal that the upstream pipeline failed.
"""

from __future__ import annotations

import re

from .base import Action, Finding


_MARKERS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\bTOP\s+SECRET\b", re.IGNORECASE), "top_secret", "critical"),
    (re.compile(r"(?<!UN)\bSECRET\b(?!\s*KEY)", re.IGNORECASE), "secret", "critical"),
    (re.compile(r"\bCUI\b|\bCONTROLLED\s+UNCLASSIFIED\s+INFORMATION\b", re.IGNORECASE), "cui", "high"),
    (re.compile(r"\bFOUO\b|\bFOR\s+OFFICIAL\s+USE\s+ONLY\b", re.IGNORECASE), "fouo", "high"),
    (re.compile(r"\bCONFIDENTIAL\b", re.IGNORECASE), "confidential", "high"),
    (re.compile(r"\bITAR\b|\bEXPORT[-\s]CONTROLLED\b", re.IGNORECASE), "itar_export_controlled", "high"),
    (re.compile(r"\bATTORNEY[-\s]CLIENT\s+PRIVILEGED?\b", re.IGNORECASE), "attorney_client", "high"),
    (re.compile(r"\bPHI\b|\bPROTECTED\s+HEALTH\s+INFORMATION\b|\bHIPAA\b", re.IGNORECASE), "phi_hipaa", "high"),
]


class ClassificationFilter:
    name = "classification_filter"
    category = "classification_marker"

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        seen_kinds: set[str] = set()
        for pattern, kind, severity in _MARKERS:
            if kind in seen_kinds:
                continue
            match = pattern.search(text)
            if match:
                seen_kinds.add(kind)
                findings.append(
                    Finding(
                        finding_id=f"OUT-CLS-{kind}-{match.start()}",
                        filter_name=self.name,
                        category="classification_marker",
                        action=Action.BLOCK,
                        severity=severity,
                        title=f"Classification marker in LLM output — {kind}",
                        matched_span=(match.start(), match.end()),
                        matched_text=match.group(0),
                        redaction_text="[BLOCKED:CLASSIFICATION]",
                        rationale=(
                            f"LLM output contains a {kind!r} marker. The model "
                            "should not produce restricted-handling markers in "
                            "user-visible content under any circumstances. "
                            "Block the response, escalate to the security team, "
                            "and audit the upstream RAG corpus and system prompt."
                        ),
                        owasp_category="LLM02",
                        atlas_techniques=["AML.T0024"],
                        airmf_subcategory="GOVERN 1.3",
                    )
                )
        return findings
