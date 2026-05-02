"""Sigma rule generator.

Produces Sigma YAML rules from a canonical Rule. Sigma is the
cross-platform detection-content format — a Sigma rule can be converted
to Elastic, Splunk, Sentinel, CrowdStrike, etc. via sigmac / pySigma.
Emitting Sigma alongside platform-specific outputs gives portability
to any SIEM the team eventually adopts.
"""

from __future__ import annotations

from .base import Condition, Rule


_SEVERITY_TO_SIGMA = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


class SigmaGenerator:
    """Render a Rule as Sigma YAML."""

    name = "sigma"
    output_subdir = "sigma"
    file_extension = ".yml"

    def filename(self, rule: Rule) -> str:
        return rule.id

    def render(self, rule: Rule) -> str:
        sel = _sigma_detection(rule.condition)

        # Tags — Sigma's tags field is a flat list of strings. We use:
        #   - attack.<owasp>     — links to OWASP LLM category
        #   - atlas.<technique>  — one entry per MITRE ATLAS technique,
        #                          formatted aml-t0051 (lowercase, dot→dash)
        #   - airmf.<subcat>     — the NIST AI RMF subcategory
        tags: list[str] = [f"attack.{rule.owasp_llm.lower()}"]
        for t in rule.mitre_atlas:
            tags.append(f"atlas.{t.lower().replace('.', '-')}")
        tags.append(f"airmf.{_airmf_tag(rule.airmf)}")
        tags_block = "\n".join(f"  - {t}" for t in tags)

        # Sigma fields list — what the detection should surface to the analyst.
        fields = list(rule.aggregation.group_by) or [rule.condition.field]
        if rule.response.drilldown_field and rule.response.drilldown_field not in fields:
            fields.append(rule.response.drilldown_field)
        fields_block = "\n".join(f"  - {f}" for f in fields)

        # Sigma falsepositives field is required for compliance with the
        # Sigma standard; populate with a reasonable default per rule.
        falsepositives = (
            "  - Authorized red-team exercises against the AI application\n"
            "  - Internal QA running probe libraries against staging targets"
        )

        return f"""title: {rule.name}
id: {_to_sigma_uuid(rule.id)}
status: experimental
description: |
  {rule.description.replace(chr(10), chr(10) + '  ')}
references:
  - https://atlas.mitre.org/
  - https://owasp.org/www-project-top-10-for-large-language-model-applications/
author: AI Security Portfolio (Project 4 generator)
date: 2026/04/30
tags:
{tags_block}
logsource:
  product: aisec
  service: {_service_from_event_type(rule.event_type)}
detection:
  selection:
{sel}
  condition: selection
fields:
{fields_block}
falsepositives:
{falsepositives}
level: {_SEVERITY_TO_SIGMA.get(rule.severity, "medium")}
"""


def _sigma_detection(c: Condition) -> str:
    op = c.operator.lower()
    val = c.value
    field = c.field
    indent = "    "
    if op == "equals":
        return f"{indent}{field}: {_sigma_value(val)}"
    if op == "in":
        if isinstance(val, (list, tuple)):
            items = "\n".join(f"{indent}  - {_sigma_value(v)}" for v in val)
            return f"{indent}{field}:\n{items}"
        return f"{indent}{field}: {_sigma_value(val)}"
    if op == "gte":
        return f"{indent}{field}|gte: {val}"
    if op == "gt":
        return f"{indent}{field}|gt: {val}"
    if op == "contains":
        return f"{indent}{field}|contains: {_sigma_value(val)}"
    return f"{indent}{field}: {_sigma_value(val)}"


def _sigma_value(v) -> str:
    if isinstance(v, str):
        # Sigma string literal — quote when ambiguous, otherwise plain.
        if any(c in v for c in [":", "#", "*", "?", "{", "}"]):
            return f'"{v}"'
        return v
    return str(v)


def _to_sigma_uuid(rule_id: str) -> str:
    """Sigma requires an ID. We deterministically derive one from the rule ID
    so regeneration produces stable IDs — important for downstream tooling
    that tracks rules by ID."""
    import hashlib

    h = hashlib.sha1(rule_id.encode("utf-8")).hexdigest()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _service_from_event_type(event_type: str) -> str:
    """Convert ai_prompt_injection -> prompt_injection for Sigma logsource.service."""
    if event_type.startswith("ai_"):
        return event_type[3:]
    return event_type


def _airmf_tag(airmf: str) -> str:
    """Convert 'MEASURE 2.7' to 'measure_2_7' for tag use."""
    return airmf.lower().replace(" ", "_").replace(".", "_")
