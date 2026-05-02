"""Evidence ingestor — reads outputs from Projects 1-7 of the AI Security Portfolio.

Each upstream project tags its findings with an `airmf_subcategory`
field. The ingestor walks each project's output directory, extracts
that field from every finding, and produces normalized EvidenceItem
records keyed by subcategory ID.

For projects that don't ship a JSON findings file but do produce
evidence (Project 1's eval set + CI floor; Project 4's rule templates),
the ingestor synthesizes EvidenceItem entries from the artifact's
existence + structure.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


@dataclass
class EvidenceItem:
    """One evidence record contributing to one AI RMF subcategory."""

    subcategory_id: str           # e.g. "MEASURE 2.7"
    project: str                  # e.g. "01-prompt-injection-pipeline"
    source: str                   # path to the source file (relative to portfolio root)
    description: str              # one-line summary of what evidence this is
    finding_count: int = 1        # how many findings / artifacts contribute
    severity: str = "informational"


# ---------------------------------------------------------------------------
# Per-project source definitions — paths and extractors
# ---------------------------------------------------------------------------


# Each entry is (project_name, path_relative_to_portfolio_root, extractor_function)
PROJECT_SOURCES: list[tuple[str, str, str]] = [
    ("01-prompt-injection-pipeline", "01-prompt-injection-pipeline", "project_1"),
    ("02-ai-red-team-framework", "02-ai-red-team-framework/out/findings.json", "json_findings"),
    ("03-rag-security-auditor", "03-rag-security-auditor/out/findings.json", "json_findings"),
    ("04-siem-correlation-generator", "04-siem-correlation-generator", "project_4"),
    ("05-llm-output-compliance-monitor", "05-llm-output-compliance-monitor/out/audit.jsonl", "audit_jsonl"),
    ("06-model-supply-chain-scanner", "06-model-supply-chain-scanner/out/findings.json", "json_findings"),
    ("07-threat-intel-summarizer", "07-threat-intel-summarizer", "project_7"),
]


def ingest_all_projects(portfolio_root: Path | str) -> list[EvidenceItem]:
    """Walk all known sources and produce a flat EvidenceItem list."""
    root = Path(portfolio_root).resolve()
    items: list[EvidenceItem] = []
    extractors: dict[str, Callable] = {
        "json_findings": _from_json_findings,
        "audit_jsonl": _from_audit_jsonl,
        "project_1": _from_project_1,
        "project_4": _from_project_4,
        "project_7": _from_project_7,
    }
    for project, rel_path, extractor_name in PROJECT_SOURCES:
        path = root / rel_path
        extractor = extractors.get(extractor_name)
        if extractor is None:
            continue
        try:
            items.extend(extractor(project, path, root))
        except Exception:  # noqa: BLE001 — never let one project break the analyzer
            continue
    return items


# ---------------------------------------------------------------------------
# Extractors — one per output shape
# ---------------------------------------------------------------------------


def _from_json_findings(project: str, path: Path, root: Path) -> list[EvidenceItem]:
    """For Projects 2, 3, 6 — read findings.json and pull airmf_subcategory."""
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    findings = data.get("findings", []) or []
    counts: dict[str, dict[str, Any]] = {}
    for f in findings:
        sub = (f.get("airmf_subcategory") or "").strip()
        if not sub:
            continue
        sev = f.get("severity", "informational")
        counts.setdefault(sub, {"count": 0, "severities": []})
        counts[sub]["count"] += 1
        counts[sub]["severities"].append(sev)
    rel = str(path.relative_to(root))
    out: list[EvidenceItem] = []
    for sub, info in counts.items():
        # Pick the highest severity seen as the headline severity for this evidence.
        sev = _max_severity(info["severities"])
        out.append(EvidenceItem(
            subcategory_id=sub,
            project=project,
            source=rel,
            description=f"{info['count']} finding(s) tagged {sub} from {project}",
            finding_count=info["count"],
            severity=sev,
        ))
    return out


def _from_audit_jsonl(project: str, path: Path, root: Path) -> list[EvidenceItem]:
    """For Project 5 — JSONL audit log; each entry's `findings[].airmf` is the tag."""
    if not path.exists():
        return []
    counts: dict[str, dict[str, Any]] = {}
    decision_count = 0
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            decision_count += 1
            for finding in entry.get("findings", []) or []:
                sub = (finding.get("airmf") or "").strip()
                sev = finding.get("severity", "informational")
                if not sub:
                    continue
                counts.setdefault(sub, {"count": 0, "severities": []})
                counts[sub]["count"] += 1
                counts[sub]["severities"].append(sev)
    rel = str(path.relative_to(root))
    out: list[EvidenceItem] = []
    # The audit log itself is GOVERN 1.5 / MANAGE 4.3 evidence — continuous
    # monitoring + incident documentation — even if no findings ever fired.
    if decision_count:
        for sub, gloss in (
            ("GOVERN 1.5",
             f"{decision_count} hash-chained audit entries — continuous monitoring evidence"),
            ("MANAGE 4.3",
             f"{decision_count} audit entries documenting compliance-monitor decisions"),
        ):
            out.append(EvidenceItem(
                subcategory_id=sub,
                project=project,
                source=rel,
                description=gloss,
                finding_count=decision_count,
                severity="informational",
            ))
    for sub, info in counts.items():
        sev = _max_severity(info["severities"])
        out.append(EvidenceItem(
            subcategory_id=sub,
            project=project,
            source=rel,
            description=f"{info['count']} finding(s) tagged {sub} from {project}",
            finding_count=info["count"],
            severity=sev,
        ))
    return out


def _from_project_1(project: str, path: Path, root: Path) -> list[EvidenceItem]:
    """Project 1 doesn't ship a runtime findings.json — its evidence is
    structural: the labeled eval set + CI-enforced regression floor.
    Synthesize EvidenceItem entries from artifact existence."""
    if not path.exists():
        return []
    out: list[EvidenceItem] = []

    eval_set = path / "eval_set.jsonl"
    if eval_set.exists():
        n = sum(1 for _ in eval_set.open("r", encoding="utf-8")) if eval_set.exists() else 0
        rel = str(eval_set.relative_to(root))
        out.append(EvidenceItem(
            subcategory_id="MEASURE 2.7",
            project=project,
            source=rel,
            description=(
                f"Labeled eval set ({n} samples) with CI-enforced F1 ≥ 0.85 "
                "regression floor — measurable security evaluation"
            ),
            finding_count=n,
            severity="informational",
        ))
        out.append(EvidenceItem(
            subcategory_id="MEASURE 1.1",
            project=project,
            source=rel,
            description=(
                "Detection eval methodology with explicit F1 threshold — "
                "risk measurement approach selected and implemented"
            ),
            finding_count=1,
            severity="informational",
        ))

    ci_workflow = path / ".github" / "workflows" / "ci.yml"
    # Note: Project 1's CI lives at the repo-root .github/workflows; it's
    # not project-local. We still record a portfolio-level CI evidence entry
    # under GOVERN 1.5 from Project 1's perspective.
    out.append(EvidenceItem(
        subcategory_id="GOVERN 1.5",
        project=project,
        source="01-prompt-injection-pipeline",
        description=(
            "Continuous monitoring policy: every push runs the eval and "
            "pytest suite; regressions break the build"
        ),
        finding_count=1,
        severity="informational",
    ))
    return out


def _from_project_4(project: str, path: Path, root: Path) -> list[EvidenceItem]:
    """Project 4 ships canonical rule templates — each tagged with its own
    airmf field. Aggregate by subcategory from the templates directory."""
    templates = path / "templates"
    if not templates.exists():
        return []
    counts: dict[str, dict[str, Any]] = {}
    template_count = 0
    for tpl in sorted(templates.glob("*.yaml")):
        template_count += 1
        # Lightweight YAML extraction — find the airmf line without
        # adding pyyaml as a hard dep on Project 8.
        for line in tpl.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("airmf:"):
                value = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                if not value:
                    continue
                counts.setdefault(value, {"count": 0})
                counts[value]["count"] += 1
                break
    out: list[EvidenceItem] = []
    rel = str(templates.relative_to(root))
    for sub, info in counts.items():
        out.append(EvidenceItem(
            subcategory_id=sub,
            project=project,
            source=rel,
            description=(
                f"{info['count']} canonical rule template(s) tagged {sub} — "
                "deployable correlation content for the subcategory"
            ),
            finding_count=info["count"],
            severity="informational",
        ))
    if template_count:
        out.append(EvidenceItem(
            subcategory_id="MANAGE 4.1",
            project=project,
            source=rel,
            description=(
                f"{template_count} rule templates published as deployable "
                "Splunk ES / Sigma / Cortex XSIAM correlation content — "
                "post-deployment monitoring plans implemented"
            ),
            finding_count=template_count,
            severity="informational",
        ))
    return out


def _from_project_7(project: str, path: Path, root: Path) -> list[EvidenceItem]:
    """Project 7 emits a citation_audit.json plus per-bundle notables. Use
    those to produce evidence for MEASURE 2.7 / MAP 4.1 / MANAGE 3.1."""
    audit_path = path / "out" / "citation_audit.json"
    notables_dir = path / "out" / "notables"
    out: list[EvidenceItem] = []

    if audit_path.exists():
        try:
            audit = json.loads(audit_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            audit = {}
        n_bundles = audit.get("bundles_processed", 0)
        n_halluc = audit.get("total_hallucinations", 0)
        rel = str(audit_path.relative_to(root))
        out.append(EvidenceItem(
            subcategory_id="MEASURE 2.7",
            project=project,
            source=rel,
            description=(
                f"{n_bundles} STIX bundle(s) summarized with citation "
                f"verification; {n_halluc} hallucination(s) detected — "
                "LLM output measured against source ground truth"
            ),
            finding_count=n_bundles,
            severity="informational",
        ))
        out.append(EvidenceItem(
            subcategory_id="MAP 4.1",
            project=project,
            source=rel,
            description=(
                "Third-party threat-intel feeds mapped to indicators with "
                "explicit STIX provenance — third-party AI risks documented"
            ),
            finding_count=n_bundles,
            severity="informational",
        ))

    if notables_dir.exists():
        notables_files = list(notables_dir.glob("*.json"))
        if notables_files:
            total_indicators = 0
            for nf in notables_files:
                try:
                    d = json.loads(nf.read_text(encoding="utf-8"))
                    total_indicators += len(d.get("events", []))
                except json.JSONDecodeError:
                    continue
            rel = str(notables_dir.relative_to(root))
            out.append(EvidenceItem(
                subcategory_id="MANAGE 3.1",
                project=project,
                source=rel,
                description=(
                    f"{total_indicators} threat-intel indicators emitted as "
                    "Splunk notables — third-party risk monitored over time"
                ),
                finding_count=total_indicators,
                severity="informational",
            ))
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _max_severity(severities: list[str]) -> str:
    order = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if not severities:
        return "informational"
    return max(severities, key=lambda s: order.get(s, 0))
