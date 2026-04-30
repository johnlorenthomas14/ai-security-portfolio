"""Report generators — findings.json + airmf_evidence.md.

Both outputs are written from the same list of finding dicts produced by
``runner.run_probe``. The Markdown report is shaped as a SOC / GRC artifact:
executive summary, findings by OWASP category, NIST AI RMF evidence keyed
by subcategory, and per-finding technical details.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


VERDICT_BADGE = {
    "pass": "PASS",
    "warning": "WARN",
    "fail": "FAIL",
}


def write_reports(
    *, findings: list[dict[str, Any]], target: Any, out_dir: Path
) -> None:
    """Write findings.json and airmf_evidence.md to out_dir."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = _summarize(findings)
    run_meta = {
        "run_time": datetime.now(timezone.utc).isoformat(),
        "target_name": target.name,
        "target_model": target.model,
        "summary": summary,
    }

    # JSON — machine-readable, Splunk-ingestible (one event per finding via
    # the `findings` array; the `run` block carries metadata).
    json_path = out_dir / "findings.json"
    with json_path.open("w", encoding="utf-8") as f:
        json.dump({"run": run_meta, "findings": findings}, f, indent=2)

    # Markdown — analyst / GRC reviewer artifact.
    md_path = out_dir / "airmf_evidence.md"
    with md_path.open("w", encoding="utf-8") as f:
        f.write(_render_markdown(findings=findings, run_meta=run_meta))


# ---------------------------------------------------------------------------
# Summary helpers
# ---------------------------------------------------------------------------


def _summarize(findings: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(findings)
    by_verdict = {"pass": 0, "warning": 0, "fail": 0}
    by_owasp: dict[str, dict[str, int]] = {}
    by_airmf: dict[str, dict[str, int]] = {}
    for f in findings:
        v = f["verdict"]
        by_verdict[v] = by_verdict.get(v, 0) + 1
        owasp = f["owasp_category"]
        by_owasp.setdefault(owasp, {"pass": 0, "warning": 0, "fail": 0})
        by_owasp[owasp][v] = by_owasp[owasp].get(v, 0) + 1
        airmf = f["airmf_subcategory"] or "(unmapped)"
        by_airmf.setdefault(airmf, {"pass": 0, "warning": 0, "fail": 0})
        by_airmf[airmf][v] = by_airmf[airmf].get(v, 0) + 1

    return {
        "n": n,
        "pass": by_verdict["pass"],
        "warning": by_verdict["warning"],
        "fail": by_verdict["fail"],
        "pass_rate": (by_verdict["pass"] / n) if n else 0.0,
        "by_owasp": by_owasp,
        "by_airmf": by_airmf,
    }


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def _render_markdown(*, findings: list[dict[str, Any]], run_meta: dict[str, Any]) -> str:
    summary = run_meta["summary"]

    lines: list[str] = []
    lines.append("# AI Red-Team Run — NIST AI RMF Evidence Report")
    lines.append("")
    lines.append(f"**Target:** `{run_meta['target_name']}` "
                 f"(model: `{run_meta['target_model']}`)  ")
    lines.append(f"**Run time:** {run_meta['run_time']}  ")
    lines.append(f"**Probes executed:** {summary['n']}  ")
    lines.append(
        f"**Result:** {summary['pass']} pass · "
        f"{summary['warning']} warning · "
        f"{summary['fail']} fail "
        f"(pass rate: {summary['pass_rate']:.0%})"
    )
    lines.append("")

    lines.append("## Executive summary")
    lines.append("")
    lines.append(_executive_summary(summary))
    lines.append("")

    lines.append("## Findings by OWASP LLM Top 10 (2025) category")
    lines.append("")
    lines.append("| Category | Probes | Pass | Warning | Fail |")
    lines.append("|---|---:|---:|---:|---:|")
    for cat, counts in sorted(summary["by_owasp"].items()):
        total = counts["pass"] + counts["warning"] + counts["fail"]
        lines.append(
            f"| {cat} | {total} | {counts['pass']} | {counts['warning']} | {counts['fail']} |"
        )
    lines.append("")

    lines.append("## NIST AI RMF 1.0 evidence (keyed by subcategory)")
    lines.append("")
    lines.append(
        "Each red-team finding contributes evidence to one AI RMF subcategory. "
        "Pass verdicts demonstrate effective control; warning and fail verdicts "
        "indicate gaps requiring Manage-function action."
    )
    lines.append("")
    lines.append("| AI RMF subcategory | Probes | Pass | Warning | Fail |")
    lines.append("|---|---:|---:|---:|---:|")
    for sub, counts in sorted(summary["by_airmf"].items()):
        total = counts["pass"] + counts["warning"] + counts["fail"]
        lines.append(
            f"| {sub} | {total} | {counts['pass']} | {counts['warning']} | {counts['fail']} |"
        )
    lines.append("")

    # Detailed findings, fails first then warnings then passes.
    order = {"fail": 0, "warning": 1, "pass": 2}
    sorted_findings = sorted(findings, key=lambda f: (order.get(f["verdict"], 9), f["probe_id"]))

    lines.append("## Detailed findings")
    lines.append("")
    for f in sorted_findings:
        lines.append(_render_finding(f))
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "*Generated by the AI Red-Team Automation Framework — Project 2 of "
        "the AI Security Portfolio.*"
    )
    return "\n".join(lines) + "\n"


def _executive_summary(summary: dict[str, Any]) -> str:
    n = summary["n"]
    fails = summary["fail"]
    warns = summary["warning"]
    if n == 0:
        return "_No probes executed._"
    if fails == 0 and warns == 0:
        return (
            f"All {n} probes passed. Target refused or otherwise resisted every "
            "attack pattern in the suite. Recommend continued monitoring and "
            "expansion of the probe suite as new attack patterns emerge."
        )
    parts: list[str] = []
    if fails:
        parts.append(
            f"**{fails}** probe(s) resulted in capitulation (verdict: fail). "
            "These represent confirmed control gaps and require immediate "
            "Manage-function action — typically a system-prompt update, "
            "input-layer detector, or output-layer guardrail."
        )
    if warns:
        parts.append(
            f"**{warns}** probe(s) returned ambiguous responses (verdict: warning). "
            "Recommend human review of those findings; if response patterns "
            "are systematic, expand the success/refusal indicator dictionaries."
        )
    parts.append(
        f"Overall pass rate: **{summary['pass_rate']:.0%}** across {n} probes."
    )
    return "\n\n".join(parts)


def _render_finding(f: dict[str, Any]) -> str:
    badge = VERDICT_BADGE.get(f["verdict"], f["verdict"].upper())
    block: list[str] = []
    block.append(f"### [{badge}] `{f['probe_id']}` — {f['title']}")
    block.append("")
    block.append(
        f"- **OWASP:** {f['owasp_category']}  · "
        f"**ATLAS:** {', '.join(f['atlas_techniques']) or '—'}  · "
        f"**AI RMF:** {f['airmf_subcategory'] or '—'}  · "
        f"**Severity:** {f['severity']}"
    )
    block.append(f"- **Rationale:** {f['rationale']}")
    if f["input_signals"]:
        block.append(
            f"- **Input recognized as attack by detector:** yes "
            f"(signals: {', '.join(f['input_signals'])})"
        )
    else:
        block.append(
            f"- **Input recognized as attack by detector:** "
            f"{'yes' if f['input_recognized_as_attack'] else 'no'}"
        )
    if f["judge_used"]:
        block.append(f"- **LLM judge:** {f['judge_verdict']}")
    block.append("")
    block.append("**Attack:**")
    block.append("")
    block.append("```")
    block.append(f["attack"].strip())
    block.append("```")
    block.append("")
    block.append("**Response excerpt:**")
    block.append("")
    block.append("```")
    block.append(f["response_excerpt"].strip() or "(empty)")
    block.append("```")
    return "\n".join(block)
