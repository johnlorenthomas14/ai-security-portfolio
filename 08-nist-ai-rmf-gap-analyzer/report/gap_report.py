"""Gap-report generators — write JSON (machine-readable) and Markdown
(GRC-reviewer-readable) outputs from a CoverageReport."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from rmf.coverage import CoverageReport


def write_reports(report: CoverageReport, out_dir: Path | str) -> tuple[Path, Path]:
    """Write `coverage.json` + `gap_report.md` to ``out_dir``."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # JSON
    json_path = out / "coverage.json"
    json_path.write_text(_to_json(report), encoding="utf-8")

    # Markdown
    md_path = out / "gap_report.md"
    md_path.write_text(_to_markdown(report), encoding="utf-8")

    return json_path, md_path


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def _to_json(report: CoverageReport) -> str:
    by_function = []
    for fc in report.function_coverage:
        by_function.append({
            "function": fc.function.value,
            "n_subcategories": fc.n_subcategories,
            "n_covered": fc.n_covered,
            "coverage_pct": round(fc.coverage_pct, 4),
        })
    subcategories = []
    for sc in sorted(report.subcategory_coverage.values(), key=lambda c: c.subcategory.id):
        subcategories.append({
            "id": sc.subcategory.id,
            "function": sc.subcategory.function.value,
            "name": sc.subcategory.name,
            "description": sc.subcategory.description,
            "priority": sc.subcategory.priority,
            "covered": sc.covered,
            "n_evidence_items": len(sc.evidence_items),
            "total_findings": sc.total_findings,
            "contributing_projects": list(sc.contributing_projects),
            "evidence": [asdict(e) for e in sc.evidence_items],
        })
    body = {
        "run": {
            "run_time": datetime.now(timezone.utc).isoformat(),
            "total_subcategories": report.total_subcategories,
            "total_covered": report.total_covered,
            "overall_pct": round(report.overall_pct, 4),
        },
        "function_coverage": by_function,
        "subcategories": subcategories,
        "gaps": [
            {
                "id": c.subcategory.id,
                "function": c.subcategory.function.value,
                "name": c.subcategory.name,
                "priority": c.subcategory.priority,
            }
            for c in report.gaps
        ],
    }
    return json.dumps(body, indent=2)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def _to_markdown(report: CoverageReport) -> str:
    lines: list[str] = []

    lines.append("# NIST AI RMF 1.0 Compliance Gap Report")
    lines.append("")
    lines.append(f"**Run time:** {datetime.now(timezone.utc).isoformat()}  ")
    lines.append(
        f"**Overall coverage:** {report.total_covered} / "
        f"{report.total_subcategories} subcategories "
        f"({report.overall_pct:.0%})"
    )
    lines.append("")

    # Function rollup
    lines.append("## Coverage by AI RMF function")
    lines.append("")
    lines.append("| Function | Subcategories | Covered | Coverage |")
    lines.append("|---|---:|---:|---:|")
    for fc in report.function_coverage:
        lines.append(
            f"| **{fc.function.value}** | {fc.n_subcategories} "
            f"| {fc.n_covered} | {fc.coverage_pct:.0%} |"
        )
    lines.append("")

    # Executive summary
    lines.append("## Executive summary")
    lines.append("")
    lines.append(_executive_summary(report))
    lines.append("")

    # Covered subcategories with evidence
    lines.append("## Covered subcategories — evidence references")
    lines.append("")
    if not report.covered_subcategories:
        lines.append("_No covered subcategories. The portfolio has not yet "
                     "produced evidence for any AI RMF subcategory._")
        lines.append("")
    for sc in report.covered_subcategories:
        lines.append(f"### `{sc.subcategory.id}` — {sc.subcategory.name}")
        lines.append("")
        lines.append(
            f"- **Function:** {sc.subcategory.function.value}  · "
            f"**Priority:** {sc.subcategory.priority}  · "
            f"**Contributing projects:** {', '.join(sc.contributing_projects)}  · "
            f"**Total findings:** {sc.total_findings}"
        )
        lines.append(f"- **Description:** {sc.subcategory.description}")
        lines.append("")
        lines.append("**Evidence:**")
        lines.append("")
        for e in sc.evidence_items:
            lines.append(f"- `{e.source}` ({e.project}) — {e.description}")
        lines.append("")

    # Gaps
    lines.append("## Gaps — subcategories with no evidence")
    lines.append("")
    gaps = report.gaps
    if not gaps:
        lines.append("_No gaps — the portfolio has produced evidence for "
                     "every catalogued AI RMF subcategory._")
        lines.append("")
        return "\n".join(lines)

    lines.append(
        "Subcategories below have **no evidence** in the current portfolio "
        "output. Priority is portfolio-relative — `high`-priority gaps are "
        "subcategories that a federal AI program would expect a "
        "Manage-function control to address."
    )
    lines.append("")
    lines.append("| Subcategory | Function | Priority | Name |")
    lines.append("|---|---|---|---|")
    for c in gaps:
        lines.append(
            f"| `{c.subcategory.id}` | {c.subcategory.function.value} "
            f"| {c.subcategory.priority} | {c.subcategory.name} |"
        )
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "*Generated by the AI Security Portfolio's NIST AI RMF Gap Analyzer "
        "— Project 8 of 8.*"
    )
    return "\n".join(lines) + "\n"


def _executive_summary(report: CoverageReport) -> str:
    n_high_gaps = sum(1 for c in report.gaps if c.subcategory.priority == "high")
    n_med_gaps = sum(1 for c in report.gaps if c.subcategory.priority == "medium")
    parts: list[str] = []
    parts.append(
        f"The AI Security Portfolio's measurable output covers "
        f"**{report.total_covered} of {report.total_subcategories}** "
        f"NIST AI RMF subcategories ({report.overall_pct:.0%})."
    )
    if n_high_gaps:
        parts.append(
            f"**{n_high_gaps} high-priority gap(s)** remain — subcategories "
            "where a federal AI program would expect a Manage-function "
            "control. See the Gaps table for the priority-ordered list."
        )
    if n_med_gaps:
        parts.append(
            f"**{n_med_gaps} medium-priority gap(s)** remain — subcategories "
            "that warrant a roadmap entry but are not blocking for an "
            "initial portfolio audit."
        )
    if not n_high_gaps and not n_med_gaps:
        parts.append(
            "No high- or medium-priority gaps remain in the catalogued "
            "subcategory subset."
        )
    return "\n\n".join(parts)
