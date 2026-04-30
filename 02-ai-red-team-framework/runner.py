"""AI Red-Team Runner.

Loads probes, fires them at a target, scores the responses, writes
findings.json and an AI RMF-aligned Markdown evidence report.

Usage:
    # Quick demo against the in-process vulnerable target (no API key):
    python runner.py --target demo

    # Real target — Anthropic Claude with a custom system prompt:
    python runner.py --target anthropic \
        --target-name "my-customer-bot" \
        --system-prompt-file system_prompt.txt

    # Use the LLM judge to disambiguate Layer-B warnings:
    python runner.py --target demo --use-judge

    # Custom output directory:
    python runner.py --target demo --output ./out
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from probes import Probe, load_probes
from scorer import ProbeScore, ProbeScorer
from targets import AnthropicTarget, DemoVulnerableTarget, TargetResponse

logger = logging.getLogger("aisec.red_team")


# ---------------------------------------------------------------------------
# Run record
# ---------------------------------------------------------------------------


def run_probe(target: Any, probe: Probe, scorer: ProbeScorer) -> dict[str, Any]:
    """Send one probe at the target and return a fully-populated finding dict."""
    response: TargetResponse = target.send(probe.attack)
    score: ProbeScore = scorer.score(
        attack=probe.attack,
        success_indicators=probe.success_indicators,
        refusal_indicators=probe.refusal_indicators,
        response_text=response.text,
        response_error=response.error,
    )
    return _finding_record(target=target, probe=probe, response=response, score=score)


def _finding_record(
    *, target: Any, probe: Probe, response: TargetResponse, score: ProbeScore
) -> dict[str, Any]:
    severity_map = {"pass": "informational", "warning": "medium", "fail": "high"}
    return {
        "probe_id": probe.id,
        "title": probe.title,
        "owasp_category": probe.owasp_category,
        "atlas_techniques": list(probe.atlas_techniques),
        "airmf_subcategory": probe.airmf_subcategory,
        "severity": probe.severity,
        "verdict": score.verdict,
        "rationale": score.rationale,
        "attack": probe.attack,
        "response_excerpt": score.response_excerpt,
        "input_recognized_as_attack": score.input_recognized_as_attack,
        "input_signals": score.input_signals,
        "success_markers_hit": score.success_markers_hit,
        "refusal_markers_hit": score.refusal_markers_hit,
        "judge_verdict": score.judge_verdict,
        "judge_used": score.judge_used,
        "target_name": target.name,
        "target_model": target.model,
        # Splunk-friendly CIM fields
        "cim_eventtype": "ai_red_team_finding",
        "signature": "ai_red_team_runner",
        "event_severity": severity_map[score.verdict],
        "event_time": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_target(args: argparse.Namespace) -> Any:
    if args.target == "demo":
        return DemoVulnerableTarget()
    if args.target == "anthropic":
        if not args.system_prompt and not args.system_prompt_file:
            raise SystemExit(
                "anthropic target requires --system-prompt or --system-prompt-file"
            )
        sp = args.system_prompt
        if args.system_prompt_file:
            sp = Path(args.system_prompt_file).read_text(encoding="utf-8")
        return AnthropicTarget(
            name=args.target_name or "anthropic-target",
            system_prompt=sp,
            model=args.model,
        )
    raise SystemExit(f"unknown target: {args.target}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AI red-team runner")
    parser.add_argument(
        "--target", default="demo", choices=["demo", "anthropic"],
        help="Target adapter to use (default: demo)",
    )
    parser.add_argument("--target-name", default=None)
    parser.add_argument("--system-prompt", default=None)
    parser.add_argument("--system-prompt-file", default=None)
    parser.add_argument("--model", default=None)
    parser.add_argument(
        "--probes-dir", default=str(Path(__file__).parent / "attack-library"),
        help="Directory containing probe YAML files",
    )
    parser.add_argument(
        "--output", default=str(Path(__file__).parent / "out"),
        help="Output directory for findings.json + airmf_evidence.md",
    )
    parser.add_argument(
        "--use-judge", action="store_true",
        help="Use the LLM judge (Anthropic) for ambiguous response cases",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Suppress per-probe stdout",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.WARNING, format="%(message)s")

    target = build_target(args)
    probes = load_probes(args.probes_dir)
    scorer = ProbeScorer(use_llm_judge=args.use_judge)

    findings: list[dict[str, Any]] = []
    for probe in probes:
        finding = run_probe(target=target, probe=probe, scorer=scorer)
        findings.append(finding)
        if not args.quiet:
            v = finding["verdict"].upper().ljust(7)
            print(f"[{v}] {probe.id}  {probe.title}")

    # Defer report writing to report.py so this runner stays focused.
    from report import write_reports
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_reports(findings=findings, target=target, out_dir=out_dir)

    summary = _summarize(findings)
    print(
        f"\n{summary['n']} probes — "
        f"{summary['pass']} pass · "
        f"{summary['warning']} warning · "
        f"{summary['fail']} fail   "
        f"(pass rate: {summary['pass_rate']:.0%})"
    )
    print(f"Wrote {out_dir}/findings.json and {out_dir}/airmf_evidence.md")

    # Exit non-zero on any fail, so this can gate CI / scheduled runs.
    return 1 if summary["fail"] else 0


def _summarize(findings: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(findings)
    counts = {"pass": 0, "warning": 0, "fail": 0}
    for f in findings:
        counts[f["verdict"]] = counts.get(f["verdict"], 0) + 1
    return {
        "n": n,
        **counts,
        "pass_rate": (counts["pass"] / n) if n else 0.0,
    }


if __name__ == "__main__":
    sys.exit(main())
