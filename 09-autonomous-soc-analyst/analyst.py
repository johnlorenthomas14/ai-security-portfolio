"""SOC Analyst Agent — CLI entry.

Loads notable events from a source (JSONL, a Project 7 notables.json,
a Project 2 findings.json, or a directory of any of the above), runs
the agent over each, and writes per-notable triage reports + an
aggregate audit JSON.

Usage:
    # Default — runs over the shipped sample notables
    python analyst.py

    # Run over a specific file or directory
    python analyst.py --notables ../07-threat-intel-summarizer/out/notables/

    # Run the eval suite (golden notables in eval/test_notables.jsonl)
    python analyst.py --eval

    # Custom output directory
    python analyst.py --output ./out
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from agent import SOCAnalystAgent, TriageReport
from eval.scorer import load_cases, score_agent
from runtime import load_notables


def _serialize_report(report: TriageReport) -> dict:
    return {
        "notable_id": report.notable_id,
        "verdict": report.verdict,
        "n_iterations": report.n_iterations,
        "input_guard": {
            "tainted": report.input_guard.tainted,
            "findings": report.input_guard.findings,
        },
        "tool_calls": report.tool_calls,
        "final_summary": report.final_summary,
        "final_escalation": report.final_escalation,
        "started_at": report.started_at,
        "completed_at": report.completed_at,
        "error": report.error,
    }


def _run_notables(args: argparse.Namespace) -> int:
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = out_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    notables = load_notables(args.notables)
    if not notables:
        print(f"No notables found at {args.notables}")
        return 0

    agent = SOCAnalystAgent(portfolio_root=Path(args.portfolio_root).resolve())

    summary_records: list[dict] = []
    for i, notable in enumerate(notables):
        report = agent.triage(notable)
        # Markdown report
        md_path = reports_dir / f"{i:03d}-{report.notable_id.replace('/', '_')[:60]}.md"
        md_path.write_text(agent.write_report_md(report), encoding="utf-8")
        summary_records.append(_serialize_report(report))
        if not args.quiet:
            print(
                f"  {report.notable_id:<40}  verdict={report.verdict:<32}  "
                f"iters={report.n_iterations}  tainted={report.input_guard.tainted}"
            )

    # Aggregate audit JSON.
    audit_path = out_dir / "triage_audit.json"
    audit_path.write_text(
        json.dumps({
            "n_notables": len(notables),
            "reports": summary_records,
        }, indent=2),
        encoding="utf-8",
    )
    print(f"\nProcessed {len(notables)} notable(s) into {out_dir}/")
    print(f"Wrote {audit_path}")
    return 0


def _run_eval(args: argparse.Namespace) -> int:
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    eval_path = Path(__file__).parent / "eval" / "test_notables.jsonl"
    cases = load_cases(eval_path)

    agent = SOCAnalystAgent(portfolio_root=Path(args.portfolio_root).resolve())
    score = score_agent(agent, cases)

    print(f"Eval — {score.n_passed} / {score.n_cases} passed "
          f"({score.pass_rate:.0%})")
    print(f"  verdict_accuracy:      {score.verdict_accuracy:.0%}")
    print(f"  tool_precision:        {score.tool_precision:.0%}")
    print(f"  input_guard_accuracy:  {score.input_guard_accuracy:.0%}")
    if not args.quiet:
        print()
        for r in score.case_results:
            mark = "PASS" if r.passed else "FAIL"
            print(
                f"  [{mark}] {r.case_id} ({r.case})  "
                f"verdict={r.actual_verdict} (expected {r.expected_verdict}); "
                f"tools_match={r.tools_match}; guard_match={r.input_guard_match}"
            )

    eval_path_out = out_dir / "eval_results.json"
    eval_path_out.write_text(
        json.dumps({
            "n_cases": score.n_cases,
            "n_passed": score.n_passed,
            "pass_rate": score.pass_rate,
            "verdict_accuracy": score.verdict_accuracy,
            "tool_precision": score.tool_precision,
            "input_guard_accuracy": score.input_guard_accuracy,
            "case_results": [
                {**asdict(r)} for r in score.case_results
            ],
        }, indent=2),
        encoding="utf-8",
    )
    print(f"\nWrote {eval_path_out}")
    # Pass-rate floor — useful as a CI gate.
    return 0 if score.pass_rate >= float(args.eval_pass_floor) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SOC Analyst Agent")
    parser.add_argument(
        "--notables",
        default=str(Path(__file__).parent / "samples" / "notables.jsonl"),
        help="Path to a notables JSONL/JSON file or a directory containing them",
    )
    parser.add_argument(
        "--portfolio-root", default=str(Path(__file__).parent.parent),
        help="Path to the AI Security Portfolio root (used by stix_lookup tool)",
    )
    parser.add_argument(
        "--output", default=str(Path(__file__).parent / "out"),
        help="Output directory for triage reports + audit JSON",
    )
    parser.add_argument("--eval", action="store_true",
                        help="Run the golden-eval suite instead of the notable corpus")
    parser.add_argument("--eval-pass-floor", default="0.75",
                        help="Minimum pass rate for --eval mode to exit 0 (default 0.75)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    if args.eval:
        return _run_eval(args)
    return _run_notables(args)


if __name__ == "__main__":
    sys.exit(main())
