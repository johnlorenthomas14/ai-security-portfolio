"""Citation verifier — extracts STIX object references from a brief and
confirms each resolves to a real object in the source bundle.

This is the security/quality control. Without verification, an LLM-
generated brief is just plausible-sounding text. With verification, every
factual claim in the brief is bound to a STIX object ID, and any
hallucinated reference is rejected before the brief reaches the analyst.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from feed.stix_types import StixBundle


# A STIX 2.1 object ID: "<type>--<uuid>". Citation conventions vary; we
# accept both bare object IDs and bracketed [object--uuid] forms because
# the brief generator's prompt requests bracketed citations.
_CITATION_RE = re.compile(
    r"\[?([a-z][a-z0-9-]+--[A-Za-z0-9-]+)\]?"
)


@dataclass
class CitationFinding:
    """One verifier finding against a generated brief."""

    citation: str           # the matched stix-id text
    resolved: bool          # True if the ID exists in the bundle
    occurrences: int = 1    # how many times the citation appears in the brief
    object_type: str = ""   # the parsed STIX object type (the part before "--")


def verify_citations(brief_markdown: str, bundle: StixBundle) -> list[CitationFinding]:
    """Walk the brief, extract every STIX-shaped citation, return a finding
    for each unique citation. `resolved=False` means the citation is a
    hallucination (the ID doesn't exist in the source bundle).

    The bundle's own ID is also considered a valid citation: the brief is
    *about* the bundle, so referencing the bundle by ID is grounded by
    definition (not a hallucination).
    """
    counts: dict[str, int] = {}
    for match in _CITATION_RE.finditer(brief_markdown):
        cite = match.group(1).strip()
        counts[cite] = counts.get(cite, 0) + 1

    findings: list[CitationFinding] = []
    for cite, n in sorted(counts.items()):
        otype = cite.split("--", 1)[0] if "--" in cite else ""
        resolved = bundle.has(cite) or cite == bundle.bundle_id
        findings.append(
            CitationFinding(
                citation=cite,
                resolved=resolved,
                occurrences=n,
                object_type=otype,
            )
        )
    return findings


def hallucinations(findings: list[CitationFinding]) -> list[CitationFinding]:
    """Subset of findings that did NOT resolve to real bundle objects."""
    return [f for f in findings if not f.resolved]


def summary(findings: list[CitationFinding]) -> dict:
    n_total = len(findings)
    n_hallucinated = sum(1 for f in findings if not f.resolved)
    return {
        "n_unique_citations": n_total,
        "n_hallucinated": n_hallucinated,
        "n_resolved": n_total - n_hallucinated,
        "hallucination_rate": (n_hallucinated / n_total) if n_total else 0.0,
    }
