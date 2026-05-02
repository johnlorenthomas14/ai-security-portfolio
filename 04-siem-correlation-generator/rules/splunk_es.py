"""Splunk ES correlation-search generator.

Emits savedsearches.conf-compatible stanzas for each canonical Rule.
Output is drop-in deployable to a Splunk Enterprise Security app.
"""

from __future__ import annotations

import re

from .base import Aggregation, Condition, Response, Rule


_WINDOW_TO_SPLUNK = {
    "1h": "-1h",
    "30m": "-30m",
    "15m": "-15m",
    "5m": "-5m",
    "1d": "-24h",
    "24h": "-24h",
    "7d": "-7d",
}

_SEVERITY_TO_NOTABLE = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


class SplunkESGenerator:
    """Render a Rule as a Splunk savedsearches.conf stanza."""

    name = "splunk_es"
    output_subdir = "splunk_es"
    file_extension = ".conf"

    def filename(self, rule: Rule) -> str:
        return rule.id

    def render(self, rule: Rule) -> str:
        spl = self._build_search(rule)
        earliest = _WINDOW_TO_SPLUNK.get(rule.aggregation.window, f"-{rule.aggregation.window}")
        notable_severity = _SEVERITY_TO_NOTABLE.get(rule.severity, "medium")

        lines: list[str] = []
        lines.append(f"# Auto-generated from rules/{rule.id}.yaml — do not edit by hand")
        lines.append(f"# OWASP: {rule.owasp_llm}  ATLAS: {', '.join(rule.mitre_atlas)}  AI RMF: {rule.airmf}")
        lines.append(f"[{rule.name}]")
        lines.append(f"description = {rule.description.replace(chr(10), ' ')}")
        lines.append(f"search = {spl}")
        lines.append(f"dispatch.earliest_time = {earliest}")
        lines.append("dispatch.latest_time = now")
        lines.append("enableSched = 1")
        lines.append("cron_schedule = */5 * * * *")
        lines.append("alert.track = 1")
        lines.append(f"alert.severity = {_severity_to_alert_int(rule.severity)}")
        if rule.response.notable_event:
            lines.append("action.notable = 1")
            lines.append(f"action.notable.param.severity = {notable_severity}")
            lines.append(f"action.notable.param.rule_title = {rule.name}")
            lines.append(f"action.notable.param.rule_description = {rule.description.replace(chr(10), ' ')}")
            if rule.response.drilldown_field:
                lines.append(f"action.notable.param.drilldown_name = Pivot on {rule.response.drilldown_field}")
                lines.append(
                    f"action.notable.param.drilldown_search = "
                    f"index={rule.source_index} sourcetype=\"{rule.sourcetype}\" "
                    f"{rule.response.drilldown_field}=\"$result.{rule.response.drilldown_field}$\""
                )
        lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------

    def _build_search(self, rule: Rule) -> str:
        cond_clause = _spl_condition(rule.condition)
        # Base search — index + sourcetype + cim_eventtype constrain the volume,
        # then the rule's condition narrows further.
        base = (
            f"index={rule.source_index} sourcetype=\"{rule.sourcetype}\" "
            f"cim_eventtype=\"{rule.event_type}\" {cond_clause}"
        )
        agg = rule.aggregation
        if agg.group_by:
            group = ", ".join(agg.group_by)
            stats = f"| stats count by {group}"
        else:
            stats = "| stats count"
        threshold = f"| where count >= {agg.threshold_count}"
        return f"{base} {stats} {threshold}"


def _spl_condition(c: Condition) -> str:
    field = c.field
    op = c.operator.lower()
    val = c.value
    if op == "equals":
        return f'{field}="{val}"'
    if op == "in":
        if isinstance(val, (list, tuple)):
            quoted = ", ".join(f'"{v}"' for v in val)
            return f"{field} IN ({quoted})"
        return f'{field}="{val}"'
    if op == "gte":
        return f"{field}>={val}"
    if op == "gt":
        return f"{field}>{val}"
    if op == "contains":
        return f'{field}="*{val}*"'
    # Unknown operators degrade to equality match for safety.
    return f'{field}="{val}"'


def _severity_to_alert_int(severity: str) -> int:
    """Splunk's alert.severity field is 1 (lowest) – 6 (highest)."""
    return {"low": 2, "medium": 3, "high": 5, "critical": 6}.get(severity, 3)
