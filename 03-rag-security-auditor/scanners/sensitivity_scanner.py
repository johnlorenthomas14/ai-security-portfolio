"""SensitivityScanner — flags classification / handling markers in corpus docs.

Catches documents that carry one of the well-known sensitivity-handling
markers federal and enterprise programs use, signaling the document was
intended for restricted distribution and should not be in a general-access
RAG corpus:

  - CUI (Controlled Unclassified Information) — modern federal default
  - FOUO (For Official Use Only) — pre-CUI federal marking, still common
  - CONFIDENTIAL / SECRET / TOP SECRET — classified-info markers
  - ITAR (International Traffic in Arms Regulations)
  - PROPRIETARY / TRADE SECRET / ATTORNEY-CLIENT — civil markers
  - PHI / HIPAA — healthcare privacy markings

A document carrying any of these markers in a corpus that's queryable by
unauthorized users is — at minimum — a policy violation, and at worst a
classified-spillage incident. Catching this at ingestion is far cheaper
than catching it via SOC alert after the LLM repeats a CUI paragraph to
an uncleared user.
"""

from __future__ import annotations

import re

from .base import Document, Finding


# Each entry: (regex, marker_kind, severity, rationale_extra)
_MARKERS: list[tuple[re.Pattern[str], str, str, str]] = [
    (
        re.compile(r"\bCUI\b|\bCONTROLLED\s+UNCLASSIFIED\s+INFORMATION\b", re.IGNORECASE),
        "cui",
        "high",
        "CUI documents must follow 32 CFR 2002 handling — restricted access lists, audit logs.",
    ),
    (
        re.compile(r"\bFOUO\b|\bFOR\s+OFFICIAL\s+USE\s+ONLY\b", re.IGNORECASE),
        "fouo",
        "high",
        "FOUO is the legacy pre-CUI federal marker; same handling implications.",
    ),
    (
        re.compile(r"\bTOP\s+SECRET\b", re.IGNORECASE),
        "top_secret",
        "critical",
        "Top Secret material in an unclassified RAG corpus is a spillage incident.",
    ),
    (
        re.compile(r"(?<!UN)\bSECRET\b", re.IGNORECASE),
        "secret",
        "critical",
        "SECRET classification markers must not appear in unclassified corpora.",
    ),
    (
        re.compile(r"\bCONFIDENTIAL\b", re.IGNORECASE),
        "confidential",
        "high",
        "Confidential markings indicate restricted distribution.",
    ),
    (
        re.compile(r"\bITAR\b|\bEXPORT[-\s]CONTROLLED\b", re.IGNORECASE),
        "itar_export_controlled",
        "high",
        "ITAR / Export-controlled material has nationality-of-recipient restrictions "
        "that an LLM cannot enforce.",
    ),
    (
        re.compile(r"\bPROPRIETARY\b|\bTRADE\s+SECRET\b", re.IGNORECASE),
        "proprietary",
        "medium",
        "Proprietary / trade-secret content may carry contractual non-disclosure obligations.",
    ),
    (
        re.compile(r"\bATTORNEY[-\s]CLIENT\s+PRIVILEGED?\b", re.IGNORECASE),
        "attorney_client",
        "high",
        "Attorney-client privilege can be waived by inclusion in an unrestricted corpus.",
    ),
    (
        re.compile(r"\bPHI\b|\bPROTECTED\s+HEALTH\s+INFORMATION\b|\bHIPAA\b", re.IGNORECASE),
        "phi_hipaa",
        "high",
        "PHI / HIPAA-covered content must be access-controlled per 45 CFR 164.",
    ),
]


class SensitivityScanner:
    """Marker-based sensitivity / classification scanner."""

    name = "sensitivity_scanner"
    category = "sensitivity_marker"

    def scan(self, document: Document) -> list[Finding]:
        findings: list[Finding] = []
        seen_kinds: set[str] = set()
        for line_idx, line in enumerate(document.text.splitlines(), start=1):
            for pattern, kind, severity, rationale_extra in _MARKERS:
                if pattern.search(line):
                    if kind in seen_kinds:
                        # One finding per kind per document — avoid noise
                        # when the marker appears on every page.
                        continue
                    seen_kinds.add(kind)
                    findings.append(
                        Finding(
                            finding_id=f"RAG-CLS-{kind}-{document.relative_path}",
                            document_path=document.relative_path,
                            scanner=self.name,
                            category=self.category,
                            severity=severity,
                            title=f"Sensitivity marker in corpus document — {kind}",
                            excerpt=line.strip()[:240],
                            line_number=line_idx,
                            owasp_category="LLM02",
                            atlas_techniques=["AML.T0024"],
                            airmf_subcategory="GOVERN 1.3",
                            rationale=(
                                f"Document carries a {kind!r} marker. "
                                f"{rationale_extra} "
                                "RAG corpora must enforce classification at the corpus "
                                "level — markers in retrievable content indicate the "
                                "document does not belong here."
                            ),
                        )
                    )
        return findings
