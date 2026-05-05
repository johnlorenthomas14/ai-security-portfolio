"""Eval scorer — runs the agent against each test notable and compares
the actual triage outcome to the golden expectation.

Three measurement axes:
  - **verdict_accuracy** — actual report.verdict matches expected_verdict.
  - **tool_precision**   — for cases with `expected_tools_called`,
                            the *exact* set called matches; for cases
                            with `expected_tools_called_min`, every
                            expected tool was called (extras allowed).
  - **input_guard_accuracy** — actual report.input_guard.tainted matches
                                expected_input_tainted.

Aggregate metric: case-pass-rate, where a case "passes" if all three
axes match.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent import SOCAnalystAgent, TriageReport


@dataclass
class EvalCase:
    """One test notable with its golden expectations."""

    id: str
    case: str
    notable: dict[str, Any]
    expected_verdict: str
    expected_tools_called: list[str] | None = None     # exact-match tools
    expected_tools_called_min: list[str] | None = None # at-least-these tools
    expected_input_tainted: bool = False
    rationale: str = ""


@dataclass
class CaseResult:
    """Result of scoring one case."""

    case_id: str
    case: str
    passed: bool
    verdict_match: bool
    tools_match: bool
    input_guard_match: bool
    expected_verdict: str
    actual_verdict: str
    expected_tools: list[str]
    actual_tools: list[str]
    expected_tainted: bool
    actual_tainted: bool
    rationale: str
    error: str = ""


@dataclass
class EvalScore:
    """Aggregate eval result."""

    n_cases: int
    n_passed: int
    case_results: list[CaseResult] = field(default_factory=list)
    verdict_accuracy: float = 0.0
    tool_precision: float = 0.0
    input_guard_accuracy: float = 0.0

    @property
    def pass_rate(self) -> float:
        return (self.n_passed / self.n_cases) if self.n_cases else 0.0


# ---------------------------------------------------------------------------


def load_cases(path: Path | str) -> list[EvalCase]:
    cases: list[EvalCase] = []
    with Path(path).open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            cases.append(EvalCase(
                id=str(raw["id"]),
                case=str(raw["case"]),
                notable=dict(raw["notable"]),
                expected_verdict=str(raw["expected_verdict"]),
                expected_tools_called=raw.get("expected_tools_called"),
                expected_tools_called_min=raw.get("expected_tools_called_min"),
                expected_input_tainted=bool(raw.get("expected_input_tainted", False)),
                rationale=str(raw.get("rationale", "")),
            ))
    return cases


def score_agent(agent: SOCAnalystAgent, cases: list[EvalCase]) -> EvalScore:
    results: list[CaseResult] = []
    n_verdict_correct = 0
    n_tools_correct = 0
    n_guard_correct = 0

    for case in cases:
        try:
            report = agent.triage(case.notable)
        except Exception as exc:  # noqa: BLE001
            results.append(CaseResult(
                case_id=case.id, case=case.case, passed=False,
                verdict_match=False, tools_match=False, input_guard_match=False,
                expected_verdict=case.expected_verdict, actual_verdict="error",
                expected_tools=case.expected_tools_called or case.expected_tools_called_min or [],
                actual_tools=[], expected_tainted=case.expected_input_tainted,
                actual_tainted=False, rationale=case.rationale, error=str(exc),
            ))
            continue

        actual_tools = [tc["tool"] for tc in report.tool_calls]
        verdict_match = report.verdict == case.expected_verdict
        tools_match = _tools_match(case, actual_tools)
        guard_match = report.input_guard.tainted == case.expected_input_tainted

        passed = verdict_match and tools_match and guard_match
        n_verdict_correct += int(verdict_match)
        n_tools_correct += int(tools_match)
        n_guard_correct += int(guard_match)

        results.append(CaseResult(
            case_id=case.id, case=case.case, passed=passed,
            verdict_match=verdict_match, tools_match=tools_match,
            input_guard_match=guard_match,
            expected_verdict=case.expected_verdict,
            actual_verdict=report.verdict,
            expected_tools=case.expected_tools_called or case.expected_tools_called_min or [],
            actual_tools=actual_tools,
            expected_tainted=case.expected_input_tainted,
            actual_tainted=report.input_guard.tainted,
            rationale=case.rationale,
        ))

    n = len(cases)
    return EvalScore(
        n_cases=n,
        n_passed=sum(1 for r in results if r.passed),
        case_results=results,
        verdict_accuracy=(n_verdict_correct / n) if n else 0.0,
        tool_precision=(n_tools_correct / n) if n else 0.0,
        input_guard_accuracy=(n_guard_correct / n) if n else 0.0,
    )


def _tools_match(case: EvalCase, actual: list[str]) -> bool:
    if case.expected_tools_called is not None:
        return actual == case.expected_tools_called
    if case.expected_tools_called_min is not None:
        return all(t in actual for t in case.expected_tools_called_min)
    return True
