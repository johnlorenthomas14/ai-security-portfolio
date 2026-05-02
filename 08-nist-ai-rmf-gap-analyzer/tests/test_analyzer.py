"""Offline tests for the NIST AI RMF Gap Analyzer.

Coverage:
  - Catalog completeness and lookup helpers.
  - Coverage computation given hand-crafted evidence.
  - Report writers produce valid JSON and well-formed Markdown.
  - End-to-end ingest against the real portfolio root (in the repo).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
PORTFOLIO_ROOT = PROJECT_DIR.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from analyzer import main as analyzer_main  # noqa: E402
from ingest import ingest_all_projects  # noqa: E402
from rmf import compute_coverage  # noqa: E402
from rmf.catalog import CATALOG, Function, by_function, by_id  # noqa: E402
from rmf.coverage import CoverageReport, EvidenceItem  # noqa: E402
from report import write_reports  # noqa: E402


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------


def test_catalog_covers_all_four_functions():
    funcs = {s.function for s in CATALOG}
    assert funcs == {Function.GOVERN, Function.MAP, Function.MEASURE, Function.MANAGE}


def test_catalog_ids_are_unique():
    ids = [s.id for s in CATALOG]
    assert len(ids) == len(set(ids))


def test_by_id_resolves_canonical_ids():
    s = by_id("MEASURE 2.7")
    assert s is not None
    assert s.function == Function.MEASURE


def test_by_id_normalizes_case():
    a = by_id("MEASURE 2.7")
    b = by_id("measure 2.7")
    c = by_id("Measure 2.7")
    assert a is b is c


def test_by_function_returns_only_that_function():
    govern = by_function(Function.GOVERN)
    assert all(s.function == Function.GOVERN for s in govern)
    assert len(govern) >= 5


# ---------------------------------------------------------------------------
# Coverage computation
# ---------------------------------------------------------------------------


def _make_evidence(*pairs: tuple[str, str]) -> list[EvidenceItem]:
    return [
        EvidenceItem(
            subcategory_id=sub,
            project=proj,
            source=f"{proj}/out/findings.json",
            description=f"test evidence for {sub}",
        )
        for sub, proj in pairs
    ]


def test_coverage_marks_covered_subcategories():
    evidence = _make_evidence(
        ("MEASURE 2.7", "01-prompt-injection-pipeline"),
        ("MEASURE 2.10", "03-rag-security-auditor"),
        ("GOVERN 1.3", "05-llm-output-compliance-monitor"),
    )
    report = compute_coverage(evidence)
    assert report.subcategory_coverage["MEASURE 2.7"].covered
    assert report.subcategory_coverage["MEASURE 2.10"].covered
    assert report.subcategory_coverage["GOVERN 1.3"].covered
    # A subcategory not in the evidence list must remain uncovered.
    assert not report.subcategory_coverage["MEASURE 4.1"].covered
    assert report.total_covered == 3


def test_coverage_aggregates_multi_project_evidence():
    evidence = _make_evidence(
        ("MEASURE 2.7", "01-prompt-injection-pipeline"),
        ("MEASURE 2.7", "02-ai-red-team-framework"),
        ("MEASURE 2.7", "07-threat-intel-summarizer"),
    )
    report = compute_coverage(evidence)
    sc = report.subcategory_coverage["MEASURE 2.7"]
    assert sc.covered
    assert len(sc.evidence_items) == 3
    assert len(sc.contributing_projects) == 3


def test_coverage_function_rollup():
    evidence = _make_evidence(
        ("MEASURE 2.7", "01-prompt-injection-pipeline"),
        ("MEASURE 2.10", "03-rag-security-auditor"),
        ("GOVERN 1.3", "05-llm-output-compliance-monitor"),
    )
    report = compute_coverage(evidence)
    fn_dict = {fc.function: fc for fc in report.function_coverage}
    assert fn_dict[Function.MEASURE].n_covered >= 2
    assert fn_dict[Function.GOVERN].n_covered >= 1
    # MAP has no evidence in this set.
    assert fn_dict[Function.MAP].n_covered == 0


def test_coverage_gaps_are_priority_ordered():
    # No evidence at all — every catalog entry is a gap.
    report = compute_coverage([])
    gaps = report.gaps
    # First several gaps should be `high` priority.
    assert any(g.subcategory.priority == "high" for g in gaps[:5])
    # Order: high → medium → low → informational.
    priorities = [g.subcategory.priority for g in gaps]
    order_values = {"high": 0, "medium": 1, "low": 2, "informational": 3}
    seen_max = -1
    for p in priorities:
        v = order_values.get(p, 9)
        assert v >= seen_max
        seen_max = v


def test_coverage_ignores_unknown_subcategory():
    """Evidence tagged with a subcategory not in the catalog should be
    silently dropped — this models the case where a downstream project
    introduces a new tag the analyzer hasn't been updated for yet."""
    evidence = _make_evidence(
        ("MEASURE 2.7", "01-prompt-injection-pipeline"),
        ("UNKNOWN 99.99", "future-project"),
    )
    report = compute_coverage(evidence)
    assert report.total_covered == 1


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------


def test_report_writers_produce_valid_outputs(tmp_path):
    evidence = _make_evidence(
        ("MEASURE 2.7", "01-prompt-injection-pipeline"),
        ("MEASURE 2.10", "03-rag-security-auditor"),
        ("GOVERN 1.3", "05-llm-output-compliance-monitor"),
    )
    report = compute_coverage(evidence)
    out = tmp_path / "out"
    json_path, md_path = write_reports(report, out)

    assert json_path.exists()
    assert md_path.exists()

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["run"]["total_covered"] == 3
    assert "function_coverage" in data
    assert "subcategories" in data
    assert "gaps" in data
    assert isinstance(data["gaps"], list)

    md = md_path.read_text(encoding="utf-8")
    assert "NIST AI RMF" in md
    assert "Coverage by AI RMF function" in md
    assert "MEASURE 2.7" in md
    # Function rollup row for each function must appear.
    for fn in ("GOVERN", "MAP", "MEASURE", "MANAGE"):
        assert f"**{fn}**" in md


# ---------------------------------------------------------------------------
# End-to-end ingest against the real portfolio root
# ---------------------------------------------------------------------------


def test_ingest_runs_against_real_portfolio_root():
    """The portfolio root has Projects 1-7 outputs from previous CI runs.
    The ingestor should produce at least some evidence — and never raise."""
    evidence = ingest_all_projects(PORTFOLIO_ROOT)
    # We can't assume specific counts (CI may have run, may not have), but
    # the call must succeed and return a list.
    assert isinstance(evidence, list)


def test_analyzer_cli_produces_outputs(tmp_path):
    out = tmp_path / "out"
    rc = analyzer_main([
        "--portfolio-root", str(PORTFOLIO_ROOT),
        "--output", str(out),
        "--quiet",
    ])
    assert rc == 0
    assert (out / "coverage.json").exists()
    assert (out / "gap_report.md").exists()
    md = (out / "gap_report.md").read_text(encoding="utf-8")
    assert "NIST AI RMF" in md
