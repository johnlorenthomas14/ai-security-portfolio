"""NIST AI RMF Compliance Gap Analyzer — CLI entry.

Walks Projects 1-7's output directories, ingests findings + their AI RMF
subcategory tags, computes per-subcategory and per-function coverage,
and writes a Markdown gap report alongside a JSON coverage document.

Usage:
    # Default — assumes the analyzer is run from inside the portfolio
    python analyzer.py

    # Explicit portfolio root (useful in CI when the working directory
    # is not the portfolio root)
    python analyzer.py --portfolio-root .. --output ./out
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Use lazy imports inside main so the module loads cleanly even when run
# without the project installed.

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NIST AI RMF Gap Analyzer")
    parser.add_argument(
        "--portfolio-root", default=str(Path(__file__).parent.parent),
        help="Path to the AI Security Portfolio root directory",
    )
    parser.add_argument(
        "--output", default=str(Path(__file__).parent / "out"),
        help="Output directory for coverage.json + gap_report.md",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    # Local imports — keeps `python analyzer.py --help` working without
    # touching the rest of the module graph.
    from ingest import ingest_all_projects
    from rmf import compute_coverage
    from rmf.coverage import EvidenceItem
    from report import write_reports

    portfolio_root = Path(args.portfolio_root).resolve()
    out_dir = Path(args.output)

    raw_evidence = ingest_all_projects(portfolio_root)
    # Reshape to coverage-module's EvidenceItem (same structure, separate type
    # to avoid a circular dep between ingest and rmf).
    evidence = [
        EvidenceItem(
            subcategory_id=e.subcategory_id,
            project=e.project,
            source=e.source,
            description=e.description,
            finding_count=e.finding_count,
            severity=e.severity,
        )
        for e in raw_evidence
    ]

    report = compute_coverage(evidence)
    json_path, md_path = write_reports(report, out_dir)

    if not args.quiet:
        print(
            f"Ingested {len(evidence)} evidence item(s) from "
            f"{len(set(e.project for e in evidence))} project(s)"
        )
        print(
            f"Coverage: {report.total_covered} / {report.total_subcategories} "
            f"subcategories ({report.overall_pct:.0%})"
        )
        for fc in report.function_coverage:
            print(
                f"  {fc.function.value:<8}  {fc.n_covered} / "
                f"{fc.n_subcategories}  ({fc.coverage_pct:.0%})"
            )
        n_high_gaps = sum(1 for g in report.gaps if g.subcategory.priority == "high")
        if n_high_gaps:
            print(f"  {n_high_gaps} high-priority gap(s) remain — see gap_report.md")
        print(f"\nWrote {json_path}")
        print(f"Wrote {md_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
