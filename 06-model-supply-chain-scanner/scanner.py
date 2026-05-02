"""AI Model Supply Chain Risk Scanner — CLI entry.

Walks a model directory, runs every Scanner against it, aggregates
findings, emits a JSON report alongside a CycloneDX 1.5 SBOM fragment.

Usage:
    # Scan the shipped demo model
    python scanner.py --model samples/demo_model

    # Scan a real HuggingFace snapshot
    python scanner.py --model /path/to/hf_snapshot --output ./out

    # Skip SBOM generation (rare — SBOM is fast and almost always wanted)
    python scanner.py --model samples/demo_model --no-sbom
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sbom import write_sbom
from scanners import (
    DependenciesScanner,
    Finding,
    ModelArtifact,
    PickleOpcodeScanner,
    ProvenanceScanner,
    Scanner,
)


def scan_model(artifact: ModelArtifact) -> list[Finding]:
    """Run all scanners over the artifact and return aggregated findings."""
    scanners: list[Scanner] = [
        PickleOpcodeScanner(),
        ProvenanceScanner(),
        DependenciesScanner(),
    ]
    findings: list[Finding] = []
    for scanner in scanners:
        try:
            findings.extend(scanner.scan(artifact))
        except Exception as exc:  # noqa: BLE001 — never let a scanner crash the run
            findings.append(_error_finding(scanner.name, exc))
    return findings


def _error_finding(scanner_name: str, exc: Exception) -> Finding:
    return Finding(
        finding_id=f"MS-ERR-{scanner_name}",
        artifact_path="<scanner-error>",
        scanner=scanner_name,
        category="scanner_error",
        severity="medium",
        title=f"Scanner {scanner_name} raised an exception",
        rationale=f"{type(exc).__name__}: {exc}",
    )


def summarize(findings: list[Finding], n_files: int) -> dict[str, Any]:
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_category: dict[str, int] = {}
    by_scanner: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1
        by_scanner[f.scanner] = by_scanner.get(f.scanner, 0) + 1
    return {
        "n_files_scanned": n_files,
        "n_findings": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
        "by_scanner": by_scanner,
    }


def _to_event(f: Finding) -> dict[str, Any]:
    """Add Splunk-friendly CIM fields to each finding."""
    severity_event = {"low": "low", "medium": "medium", "high": "high",
                      "critical": "critical"}.get(f.severity, "low")
    return {
        **asdict(f),
        "cim_eventtype": "ai_model_supply_chain_finding",
        "signature": "model_supply_chain_scanner",
        "event_severity": severity_event,
        "event_time": datetime.now(timezone.utc).isoformat(),
    }


def write_report(findings: list[Finding], summary: dict[str, Any],
                 model_root: Path, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    findings_path = out_dir / "findings.json"
    report_path = out_dir / "audit_report.md"

    findings_path.write_text(
        json.dumps({
            "run": {
                "run_time": datetime.now(timezone.utc).isoformat(),
                "model_root": str(model_root),
                "summary": summary,
            },
            "findings": [_to_event(f) for f in findings],
        }, indent=2),
        encoding="utf-8",
    )
    report_path.write_text(_render_markdown(findings, summary, model_root), encoding="utf-8")
    return findings_path, report_path


def _render_markdown(findings: list[Finding], summary: dict[str, Any],
                     model_root: Path) -> str:
    sev = summary["by_severity"]
    lines: list[str] = []
    lines.append("# AI Model Supply Chain Audit")
    lines.append("")
    lines.append(f"**Model root:** `{model_root}`  ")
    lines.append(f"**Files scanned:** {summary['n_files_scanned']}  ")
    lines.append(f"**Findings:** {summary['n_findings']}")
    lines.append("")
    lines.append("## Severity rollup")
    lines.append("")
    lines.append("| Critical | High | Medium | Low |")
    lines.append("|---:|---:|---:|---:|")
    lines.append(
        f"| {sev.get('critical', 0)} | {sev.get('high', 0)} "
        f"| {sev.get('medium', 0)} | {sev.get('low', 0)} |"
    )
    lines.append("")
    lines.append("## Findings by scanner")
    lines.append("")
    lines.append("| Scanner | Findings |")
    lines.append("|---|---:|")
    for scanner, count in sorted(summary["by_scanner"].items()):
        lines.append(f"| {scanner} | {count} |")
    lines.append("")
    if not findings:
        lines.append("_No findings — the model directory passed all scanners._")
        return "\n".join(lines) + "\n"
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_findings = sorted(
        findings,
        key=lambda f: (severity_order.get(f.severity, 9), f.scanner, f.artifact_path),
    )
    lines.append("## Detailed findings")
    lines.append("")
    for f in sorted_findings:
        lines.append(f"### [{f.severity.upper()}] `{f.finding_id}` — {f.title}")
        lines.append("")
        line_ref = f"L{f.line_number}" if f.line_number else "—"
        lines.append(
            f"- **Artifact:** `{f.artifact_path}` (line {line_ref})  · "
            f"**Scanner:** {f.scanner}  · **Category:** {f.category}"
        )
        lines.append(
            f"- **OWASP:** {f.owasp_category or '—'}  · "
            f"**ATLAS:** {', '.join(f.atlas_techniques) or '—'}  · "
            f"**AI RMF:** {f.airmf_subcategory or '—'}"
        )
        lines.append(f"- **Rationale:** {f.rationale}")
        if f.matched_evidence:
            lines.append("")
            lines.append("**Evidence:**")
            lines.append("")
            lines.append("```")
            lines.append(f.matched_evidence[:480])
            lines.append("```")
        lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AI Model Supply Chain Scanner")
    parser.add_argument(
        "--model", default=str(Path(__file__).parent / "samples" / "demo_model"),
        help="Path to the model directory to scan",
    )
    parser.add_argument(
        "--output", default=str(Path(__file__).parent / "out"),
        help="Output directory for findings.json, audit_report.md, and sbom.cdx.json",
    )
    parser.add_argument("--no-sbom", action="store_true",
                        help="Skip CycloneDX SBOM generation")
    parser.add_argument("--source-url", default=None,
                        help="Optional URL the model was distributed from "
                             "(recorded in SBOM externalReferences)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    model_root = Path(args.model).resolve()
    out_dir = Path(args.output)

    artifact = ModelArtifact(root=model_root)
    n_files = sum(1 for _ in artifact.files())
    findings = scan_model(artifact)
    summary = summarize(findings, n_files)

    findings_path, report_path = write_report(findings, summary, model_root, out_dir)

    sbom_path = None
    if not args.no_sbom:
        sbom_path = write_sbom(
            artifact, out_dir / "sbom.cdx.json",
            model_name=model_root.name,
            source_url=args.source_url,
        )

    if not args.quiet:
        print(f"Scanned {summary['n_files_scanned']} files in {model_root}")
        print(
            f"  Findings: {summary['n_findings']}  ("
            f"critical={summary['by_severity'].get('critical', 0)} "
            f"high={summary['by_severity'].get('high', 0)} "
            f"medium={summary['by_severity'].get('medium', 0)} "
            f"low={summary['by_severity'].get('low', 0)})"
        )
        for f in findings:
            line_ref = f":{f.line_number}" if f.line_number else ""
            print(f"  [{f.severity.upper():<8}] {f.artifact_path}{line_ref}  {f.title}")
        print(f"\nWrote {findings_path}")
        print(f"Wrote {report_path}")
        if sbom_path:
            print(f"Wrote {sbom_path}")

    # Exit non-zero on critical/high findings — useful as a CI / pre-deploy gate.
    severe = summary["by_severity"].get("critical", 0) + summary["by_severity"].get("high", 0)
    return 1 if severe else 0


if __name__ == "__main__":
    sys.exit(main())
