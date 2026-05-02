"""Coverage analysis — compute per-subcategory and per-function coverage
from the ingested EvidenceItems."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .catalog import CATALOG, AIRMFSubcategory, Function


@dataclass
class EvidenceItem:
    """Mirror of ingest.EvidenceItem to avoid a circular import."""

    subcategory_id: str
    project: str
    source: str
    description: str
    finding_count: int = 1
    severity: str = "informational"


@dataclass
class SubcategoryCoverage:
    """Per-subcategory coverage record."""

    subcategory: AIRMFSubcategory
    evidence_items: list[EvidenceItem] = field(default_factory=list)
    contributing_projects: list[str] = field(default_factory=list)

    @property
    def covered(self) -> bool:
        return len(self.evidence_items) > 0

    @property
    def total_findings(self) -> int:
        return sum(e.finding_count for e in self.evidence_items)


@dataclass
class FunctionCoverage:
    """Per-function (Govern/Map/Measure/Manage) rollup."""

    function: Function
    n_subcategories: int
    n_covered: int

    @property
    def coverage_pct(self) -> float:
        return (self.n_covered / self.n_subcategories) if self.n_subcategories else 0.0


@dataclass
class CoverageReport:
    """Whole-portfolio coverage analysis."""

    subcategory_coverage: dict[str, SubcategoryCoverage]
    function_coverage: list[FunctionCoverage]
    total_subcategories: int
    total_covered: int
    evidence_items: list[EvidenceItem]

    @property
    def overall_pct(self) -> float:
        return (self.total_covered / self.total_subcategories) if self.total_subcategories else 0.0

    @property
    def gaps(self) -> list[SubcategoryCoverage]:
        """Subcategories with zero evidence, ordered by priority then ID."""
        order = {"high": 0, "medium": 1, "low": 2, "informational": 3}
        gaps = [c for c in self.subcategory_coverage.values() if not c.covered]
        return sorted(
            gaps,
            key=lambda c: (order.get(c.subcategory.priority, 9), c.subcategory.id),
        )

    @property
    def covered_subcategories(self) -> list[SubcategoryCoverage]:
        """Subcategories with at least one evidence item, ordered by ID."""
        return sorted(
            (c for c in self.subcategory_coverage.values() if c.covered),
            key=lambda c: c.subcategory.id,
        )


def compute_coverage(evidence: list[EvidenceItem]) -> CoverageReport:
    """Build a CoverageReport from the evidence list."""
    sub_cov: dict[str, SubcategoryCoverage] = {
        s.id: SubcategoryCoverage(subcategory=s) for s in CATALOG
    }
    for item in evidence:
        if item.subcategory_id not in sub_cov:
            # Evidence references a subcategory not in our catalog — skip
            # silently. Real production analyzers would log this for review.
            continue
        sub_cov[item.subcategory_id].evidence_items.append(item)
        if item.project not in sub_cov[item.subcategory_id].contributing_projects:
            sub_cov[item.subcategory_id].contributing_projects.append(item.project)

    fn_cov: list[FunctionCoverage] = []
    for fn in Function:
        subs = [s for s in CATALOG if s.function == fn]
        n_total = len(subs)
        n_cov = sum(1 for s in subs if sub_cov[s.id].covered)
        fn_cov.append(FunctionCoverage(
            function=fn, n_subcategories=n_total, n_covered=n_cov,
        ))

    total = len(CATALOG)
    covered = sum(1 for c in sub_cov.values() if c.covered)
    return CoverageReport(
        subcategory_coverage=sub_cov,
        function_coverage=fn_cov,
        total_subcategories=total,
        total_covered=covered,
        evidence_items=evidence,
    )
