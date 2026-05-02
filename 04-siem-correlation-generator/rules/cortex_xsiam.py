"""Cortex XSIAM XQL correlation-rule generator.

XQL (Cortex Query Language) is XSIAM's native query/correlation
language. Output is a `.xql` file with the XQL query, plus a Markdown
header documenting the rule's mapping to ATLAS/OWASP/AI RMF since
XQL itself doesn't have rich rule-metadata fields the way Splunk ES
savedsearches.conf or Sigma do.
"""

from __future__ import annotations

from .base import Aggregation, Condition, Rule


_SEVERITY_TO_XSIAM = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


class CortexXSIAMGenerator:
    """Render a Rule as a Cortex XSIAM XQL correlation query."""

    name = "cortex_xsiam"
    output_subdir = "cortex_xsiam"
    file_extension = ".xql"

    def filename(self, rule: Rule) -> str:
        return rule.id

    def render(self, rule: Rule) -> str:
        cond = _xql_condition(rule.condition)
        agg = rule.aggregation
        if agg.group_by:
            group_clause = ", ".join(agg.group_by)
            comp = (
                f"| comp count() as event_count, "
                f"values(atlas_techniques) as atlas, "
                f"values(severity) as severities "
                f"by {group_clause}"
            )
        else:
            comp = "| comp count() as event_count"

        threshold = f"| filter event_count >= {agg.threshold_count}"

        # Map our window keys to XQL's _time filtering pattern.
        window_seconds = _window_to_seconds(agg.window)
        time_filter = f"| filter _time >= to_timestamp(current_time() - {window_seconds})"

        # Header block — XQL doesn't have a metadata syntax, so we encode
        # it as comments at the top of the file.
        header = (
            f"// rule_id: {rule.id}\n"
            f"// name: {rule.name}\n"
            f"// severity: {rule.severity}\n"
            f"// owasp: {rule.owasp_llm}\n"
            f"// atlas: {', '.join(rule.mitre_atlas) or '(none)'}\n"
            f"// airmf: {rule.airmf}\n"
            f"// description: {rule.description.replace(chr(10), ' ')}\n"
            f"//\n"
            f"// Recommended XSIAM rule severity: {_SEVERITY_TO_XSIAM.get(rule.severity, 'medium')}\n"
            f"// Drilldown field: {rule.response.drilldown_field or '(none)'}\n"
            f"// Recommended action: {rule.response.recommended_action.replace(chr(10), ' ')}\n"
        )

        dataset = _dataset_from_event_type(rule.event_type)
        query = (
            f"dataset = {dataset}\n"
            f"{time_filter}\n"
            f"| filter cim_eventtype = \"{rule.event_type}\"\n"
            f"| filter {cond}\n"
            f"{comp}\n"
            f"{threshold}\n"
            f"| alter alert_severity = \"{_SEVERITY_TO_XSIAM.get(rule.severity, 'medium')}\""
        )

        return header + "\n" + query + "\n"


def _xql_condition(c: Condition) -> str:
    field = c.field
    op = c.operator.lower()
    val = c.value
    if op == "equals":
        if isinstance(val, str):
            return f'{field} = "{val}"'
        return f"{field} = {val}"
    if op == "in":
        if isinstance(val, (list, tuple)):
            quoted = ", ".join(f'"{v}"' if isinstance(v, str) else str(v) for v in val)
            return f"{field} in ({quoted})"
        return f'{field} = "{val}"'
    if op == "gte":
        return f"{field} >= {val}"
    if op == "gt":
        return f"{field} > {val}"
    if op == "contains":
        return f'{field} contains "{val}"'
    return f'{field} = "{val}"'


def _dataset_from_event_type(event_type: str) -> str:
    """ai_prompt_injection -> aisec_prompt_injection (XSIAM dataset naming)."""
    if event_type.startswith("ai_"):
        return f"aisec_{event_type[3:]}"
    return f"aisec_{event_type}"


def _window_to_seconds(window: str) -> int:
    """Translate '1h', '30m', '15m', '1d' to seconds for XQL time filtering."""
    table = {
        "1h": 3600, "30m": 1800, "15m": 900, "5m": 300,
        "1d": 86400, "24h": 86400, "7d": 604800,
    }
    return table.get(window, 3600)
