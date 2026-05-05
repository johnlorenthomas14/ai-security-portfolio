"""SOCAnalystAgent — autonomous tool-use loop over a notable event.

Trust boundary:
  - The notable's content is treated as untrusted text. The InputGuard
    scans it through Project 1's detector before the agent loop starts.
    If the input is tainted, the agent is forced into "escalate-only"
    mode: it can call escalate_to_human and summarize, but no other
    tool that would let attacker-controlled instructions in the notable
    drive autonomous action.
  - The LLM never executes Python. It selects a tool name + arguments;
    the agent dispatches to the matching Tool object.

Termination:
  - summarize tool called → verdict = triaged
  - escalate_to_human tool called → verdict = escalate
  - max_iterations exceeded → verdict = max_iterations_exceeded
    (treated as escalation)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runtime.input_guard import InputGuard, InputGuardResult
from tools import Tool, ToolCall, ToolResult, default_tools, registry
from tools.escalate import EscalateToHumanTool
from tools.summarize import SummarizeTool


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class TriageReport:
    """The end-to-end result of triaging one notable."""

    notable_id: str
    verdict: str               # triaged | escalate | max_iterations_exceeded | input_tainted
    final_summary: dict[str, Any] = field(default_factory=dict)
    final_escalation: dict[str, Any] = field(default_factory=dict)
    input_guard: InputGuardResult = field(default_factory=InputGuardResult)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    n_iterations: int = 0
    error: str | None = None
    started_at: str = ""
    completed_at: str = ""


# ---------------------------------------------------------------------------
# Stub LLM client — the deterministic offline brain
# ---------------------------------------------------------------------------


class StubAgentClient:
    """Deterministic tool-selector for offline / CI runs.

    The stub implements a small policy table that picks a tool based on
    the notable's structure and the agent's accumulated context. It is
    NOT meant to be a substitute for a real LLM — it's a policy that
    exercises the agent's full code path so the loop, input guard, and
    tools can be regression-tested without an API call.
    """

    name = "stub"

    def decide(self, *, notable: dict[str, Any], history: list[ToolResult],
                input_tainted: bool, available_tools: list[str],
                iteration: int) -> ToolCall:
        called = {h.tool_name for h in history}

        # Tainted input → escalate immediately, do not run other tools.
        if input_tainted and "escalate_to_human" in available_tools:
            return ToolCall(
                tool_name="escalate_to_human",
                arguments={
                    "reason": (
                        "Notable content tripped Project 1's input-injection "
                        "detector — agent declines to run autonomous tool "
                        "calls on attacker-controlled text."
                    ),
                    "recommended_action": "Human analyst review of the notable's payload.",
                    "severity": "high",
                },
            )

        # Critical-severity finding (RAG credential leak, supply-chain
        # critical, classification spillage) → escalate immediately. Some
        # notable shapes lack `verdict` / IP / atlas tags but ship a
        # `severity: critical` field that's the actionable signal on its own.
        severity = str(notable.get("severity", "")).lower()
        if severity == "critical" and not called and "escalate_to_human" in available_tools:
            return ToolCall(
                tool_name="escalate_to_human",
                arguments={
                    "reason": (
                        f"Critical-severity finding: "
                        f"{notable.get('title') or notable.get('category') or notable.get('cim_eventtype', 'unknown')}. "
                        "Critical findings require human authorization for "
                        "remediation actions (credential rotation, document "
                        "removal, classification incident response)."
                    ),
                    "recommended_action": (
                        "Review the source artifact, take remediation per "
                        "category — rotate credentials, remove document from "
                        "corpus, or invoke classification-spillage process."
                    ),
                    "severity": "critical",
                },
            )

        # Step 1: search for related events around the same user / app.
        if "splunk_search" not in called and "splunk_search" in available_tools:
            user = notable.get("user", "")
            app = notable.get("app", "")
            filters = []
            if user:
                filters.append(f"user={user}")
            if app:
                filters.append(f"app={app}")
            if not filters:
                # Fall back to verdict if user/app aren't available.
                v = notable.get("verdict", "malicious")
                filters.append(f"verdict={v}")
            return ToolCall(
                tool_name="splunk_search",
                arguments={"filters": ",".join(filters), "max_results": 10},
            )

        # Step 2: enrich the source IP / indicator — but skip when the
        # only available indicator is internal (RFC1918). Internal IPs
        # aren't actionable in IOC-enrichment terms; skipping keeps the
        # audit trail tight.
        if "ioc_enrichment" not in called and "ioc_enrichment" in available_tools:
            indicator = self._pick_actionable_indicator(notable)
            if indicator:
                return ToolCall(
                    tool_name="ioc_enrichment",
                    arguments={"indicator": indicator},
                )

        # Step 3: ATLAS lookup for any technique tagged on the notable.
        if "atlas_lookup" not in called and "atlas_lookup" in available_tools:
            techniques = (
                notable.get("atlas_techniques") or notable.get("atlas") or []
            )
            if techniques:
                return ToolCall(
                    tool_name="atlas_lookup",
                    arguments={"technique_id": techniques[0]},
                )

        # Step 4: STIX cross-reference for the indicator. Skip when no
        # actionable (non-internal) indicator exists.
        if "stix_lookup" not in called and "stix_lookup" in available_tools:
            indicator = self._pick_actionable_indicator(notable)
            if indicator:
                return ToolCall(
                    tool_name="stix_lookup",
                    arguments={"query": indicator},
                )

        # Step 5: decide outcome based on enrichment + history.
        ioc_verdict = self._enrichment_verdict(history)
        notable_verdict = str(notable.get("verdict", "")).lower()

        if ioc_verdict == "malicious" or notable_verdict == "malicious":
            return ToolCall(
                tool_name="escalate_to_human",
                arguments={
                    "reason": (
                        "Confirmed malicious indicator and/or notable verdict — "
                        "blocking action requires human authorization."
                    ),
                    "recommended_action": (
                        "Block source IP / domain at perimeter; review user "
                        "session for downstream actions; rotate any "
                        "credentials the user could have reached."
                    ),
                    "severity": "high",
                },
            )

        return ToolCall(
            tool_name="summarize",
            arguments={
                "verdict": "false_positive" if notable_verdict == "benign" else "suspicious",
                "summary": self._compose_summary(notable, history),
                "key_evidence": self._collect_evidence(history),
                "recommended_action": (
                    "Close as false positive" if notable_verdict == "benign"
                    else "Monitor for repeat occurrences from the same user/app."
                ),
            },
        )

    # ------------------------------------------------------------------

    @staticmethod
    def _pick_actionable_indicator(notable: dict[str, Any]) -> str | None:
        """Like _pick_indicator but rejects internal RFC1918 IPv4 addresses
        — there's nothing to enrich on a private IP, and STIX has no
        crossover. Returns None if the only candidate is internal-only."""
        ind = StubAgentClient._pick_indicator(notable, [])
        if ind is None:
            return None
        if StubAgentClient._is_rfc1918(ind):
            return None
        return ind

    @staticmethod
    def _is_rfc1918(value: str) -> bool:
        """Return True if `value` looks like an RFC1918 IPv4 address."""
        import re
        if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value):
            return False
        if value.startswith(("10.", "192.168.")):
            return True
        # 172.16.0.0 – 172.31.255.255
        parts = value.split(".")
        if parts[0] == "172":
            try:
                return 16 <= int(parts[1]) <= 31
            except ValueError:
                return False
        return False

    @staticmethod
    def _pick_indicator(notable: dict[str, Any], history: list[ToolResult]) -> str | None:
        """Pick the most-actionable indicator from the notable."""
        for key in ("src_ip", "indicator_value", "indicator_values"):
            value = notable.get(key)
            if isinstance(value, list) and value:
                return str(value[0])
            if isinstance(value, str) and value:
                return value
        return None

    @staticmethod
    def _enrichment_verdict(history: list[ToolResult]) -> str:
        for h in history:
            if h.tool_name == "ioc_enrichment" and h.output.get("verdict") == "malicious":
                return "malicious"
        return "unknown"

    @staticmethod
    def _compose_summary(notable: dict[str, Any], history: list[ToolResult]) -> str:
        parts = [
            f"Triage of notable for user={notable.get('user', 'unknown')} "
            f"app={notable.get('app', 'unknown')}: notable verdict "
            f"{notable.get('verdict', 'unknown')!r}.",
        ]
        for h in history:
            if h.tool_name == "splunk_search":
                n = h.output.get("matched", 0)
                parts.append(f"Splunk search returned {n} related event(s).")
            if h.tool_name == "ioc_enrichment":
                parts.append(
                    f"IOC enrichment verdict: {h.output.get('verdict', 'unknown')}."
                )
        return " ".join(parts)

    @staticmethod
    def _collect_evidence(history: list[ToolResult]) -> list[str]:
        evidence: list[str] = []
        for h in history:
            if h.tool_name == "atlas_lookup" and h.output.get("found"):
                evidence.append(
                    f"ATLAS {h.output['technique_id']} — {h.output['name']}"
                )
            if h.tool_name == "stix_lookup":
                for obj in h.output.get("objects", []) or []:
                    evidence.append(
                        f"STIX {obj.get('type')} {obj.get('id')} — {obj.get('name', '')}"
                    )
            if h.tool_name == "ioc_enrichment":
                evidence.append(
                    f"IOC enrichment: {h.output.get('verdict', 'unknown')} "
                    f"(reputation {h.output.get('reputation', 0)})"
                )
        return evidence


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------


class SOCAnalystAgent:
    """Autonomous SOC analyst tool-use loop."""

    def __init__(
        self,
        *,
        tools: list[Tool] | None = None,
        portfolio_root: Path | str | None = None,
        input_guard: InputGuard | None = None,
        client: Any | None = None,
        offline: bool = False,
        max_iterations: int = 8,
    ) -> None:
        self._tools = tools or default_tools(portfolio_root=portfolio_root)
        self._registry = registry(self._tools)
        self._guard = input_guard or InputGuard()
        self._max_iterations = max_iterations
        self._offline = offline or not os.environ.get("ANTHROPIC_API_KEY")
        self._client = client
        # In MVP, when not offline and no client provided, we still default to
        # the stub client. A live-Claude tool-use implementation is on the
        # roadmap — the deterministic stub already exercises the full agent
        # surface for portfolio / CI purposes.
        self._stub = StubAgentClient()

    # ------------------------------------------------------------------

    def triage(self, notable: dict[str, Any]) -> TriageReport:
        notable_id = str(notable.get("probe_id") or notable.get("indicator_id")
                         or notable.get("finding_id") or notable.get("id")
                         or notable.get("event_time", "unknown"))
        report = TriageReport(
            notable_id=notable_id, verdict="pending",
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        # 1. Input-guard pass.
        guard_result = self._guard.scan(notable)
        report.input_guard = guard_result

        # 2. Tool-use loop.
        history: list[ToolResult] = []
        available = list(self._registry.keys())

        for i in range(self._max_iterations):
            report.n_iterations = i + 1
            decider = self._stub  # MVP — stub for both offline + online.
            try:
                tool_call = decider.decide(
                    notable=notable,
                    history=history,
                    input_tainted=guard_result.tainted,
                    available_tools=available,
                    iteration=i,
                )
            except Exception as exc:  # noqa: BLE001
                report.error = f"decider error: {exc}"
                report.verdict = "error"
                break

            tool = self._registry.get(tool_call.tool_name)
            if tool is None:
                report.error = f"unknown tool requested: {tool_call.tool_name}"
                report.verdict = "error"
                break

            try:
                output = tool.invoke(tool_call.arguments)
                result = ToolResult(
                    tool_name=tool_call.tool_name,
                    arguments=dict(tool_call.arguments),
                    output=output,
                )
            except Exception as exc:  # noqa: BLE001 — tools should not raise, but be safe
                result = ToolResult(
                    tool_name=tool_call.tool_name,
                    arguments=dict(tool_call.arguments),
                    output={},
                    error=str(exc),
                )

            history.append(result)
            report.tool_calls.append({
                "iteration": i + 1,
                "tool": result.tool_name,
                "arguments": result.arguments,
                "output": result.output,
                "error": result.error,
            })

            # Termination conditions.
            if isinstance(tool, SummarizeTool):
                report.verdict = "input_tainted_triaged" if guard_result.tainted else "triaged"
                report.final_summary = result.output
                break
            if isinstance(tool, EscalateToHumanTool):
                report.verdict = "input_tainted_escalated" if guard_result.tainted else "escalate"
                report.final_escalation = result.output
                break
        else:
            report.verdict = "max_iterations_exceeded"

        report.completed_at = datetime.now(timezone.utc).isoformat()
        return report

    # ------------------------------------------------------------------

    def write_report_md(self, report: TriageReport) -> str:
        """Render a TriageReport as analyst-readable markdown."""
        lines: list[str] = []
        lines.append(f"# Triage Report — `{report.notable_id}`")
        lines.append("")
        lines.append(f"**Verdict:** {report.verdict}  ")
        lines.append(f"**Iterations:** {report.n_iterations}  ")
        lines.append(f"**Input-guard tainted:** {report.input_guard.tainted}  ")
        if report.error:
            lines.append(f"**Error:** {report.error}  ")
        lines.append("")

        if report.input_guard.findings:
            lines.append("## Input-guard findings")
            lines.append("")
            for f in report.input_guard.findings:
                lines.append(
                    f"- **{f['field']}** — {f['verdict']} (signals: "
                    f"{', '.join(f['signals'])})"
                )
            lines.append("")

        if report.final_summary:
            s = report.final_summary
            lines.append("## Summary")
            lines.append("")
            lines.append(f"**Triage verdict:** {s.get('verdict', '?')}")
            lines.append("")
            lines.append(s.get("summary", ""))
            evidence = s.get("key_evidence", []) or []
            if evidence:
                lines.append("")
                lines.append("**Key evidence:**")
                for e in evidence:
                    lines.append(f"- {e}")
            if s.get("recommended_action"):
                lines.append("")
                lines.append(f"**Recommended action:** {s['recommended_action']}")
            lines.append("")

        if report.final_escalation:
            e = report.final_escalation
            lines.append("## Escalation")
            lines.append("")
            lines.append(f"**Reason:** {e.get('reason', '')}")
            lines.append("")
            lines.append(f"**Severity:** {e.get('severity', 'medium')}")
            lines.append("")
            if e.get("recommended_action"):
                lines.append(f"**Recommended action:** {e['recommended_action']}")
            lines.append("")

        lines.append("## Audit trail")
        lines.append("")
        for call in report.tool_calls:
            lines.append(
                f"- **#{call['iteration']}** `{call['tool']}` — "
                f"args: `{json.dumps(call['arguments'])[:160]}`"
            )
        return "\n".join(lines) + "\n"
