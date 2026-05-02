"""Canonical Rule schema and the generator protocol.

A Rule is loaded once from YAML and consumed by every generator. The
schema is deliberately simple and SIEM-agnostic — fields name *what*
the rule looks for, not how a specific platform expresses it. Each
generator translates the canonical condition + aggregation + response
into its target's native query language.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import yaml


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Condition:
    """Match clause — what makes one event interesting."""

    field: str                 # e.g., "verdict"
    operator: str              # equals | in | gte | gt | contains
    value: Any                 # str | list[str] | int


@dataclass(frozen=True)
class Aggregation:
    """How to roll up matching events into an alertable signal."""

    group_by: tuple[str, ...]  # e.g., ("user", "app", "src_ip")
    threshold_count: int       # min events to alert
    window: str                # "1h", "30m", "1d" — translated per-platform


@dataclass(frozen=True)
class Response:
    """Analyst-facing bookkeeping — drilldown, recommended action, severity."""

    notable_event: bool
    drilldown_field: str       # field to pivot on after the alert fires
    recommended_action: str    # short prose for the analyst


@dataclass(frozen=True)
class Rule:
    """A canonical detection rule. One YAML per Rule, one Rule per detection."""

    id: str                          # e.g., "AIPI-001"
    name: str
    description: str
    source_index: str                # Splunk index hint; "aisec" for the portfolio
    sourcetype: str                  # e.g., "aisec:prompt_injection"
    event_type: str                  # CIM eventtype, e.g., "ai_prompt_injection"
    severity: str                    # low | medium | high | critical
    mitre_atlas: tuple[str, ...]     # ATLAS technique IDs
    owasp_llm: str                   # e.g., "LLM01"
    airmf: str                       # e.g., "MEASURE 2.7"
    condition: Condition
    aggregation: Aggregation
    response: Response


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def load_rule(path: Path | str) -> Rule:
    """Load one YAML file into a Rule object."""
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return _to_rule(raw)


def load_rules(directory: Path | str) -> list[Rule]:
    """Load every *.yaml in `directory` (sorted)."""
    d = Path(directory)
    if not d.exists():
        raise FileNotFoundError(f"Templates directory not found: {d}")
    rules = [load_rule(p) for p in sorted(d.glob("*.yaml"))]
    if not rules:
        raise ValueError(f"No rule templates found in {d}")
    return rules


def _to_rule(raw: dict[str, Any]) -> Rule:
    cond_raw = raw["condition"]
    agg_raw = raw["aggregation"]
    resp_raw = raw["response"]
    return Rule(
        id=str(raw["id"]),
        name=str(raw["name"]),
        description=str(raw.get("description", "")).strip(),
        source_index=str(raw.get("source_index", "aisec")),
        sourcetype=str(raw["sourcetype"]),
        event_type=str(raw["event_type"]),
        severity=str(raw.get("severity", "medium")),
        mitre_atlas=tuple(raw.get("mitre_atlas", []) or []),
        owasp_llm=str(raw.get("owasp_llm", "")),
        airmf=str(raw.get("airmf", "")),
        condition=Condition(
            field=str(cond_raw["field"]),
            operator=str(cond_raw["operator"]),
            value=cond_raw["value"],
        ),
        aggregation=Aggregation(
            group_by=tuple(agg_raw.get("group_by", []) or []),
            threshold_count=int(agg_raw.get("threshold_count", 1)),
            window=str(agg_raw.get("window", "1h")),
        ),
        response=Response(
            notable_event=bool(resp_raw.get("notable_event", True)),
            drilldown_field=str(resp_raw.get("drilldown_field", "")),
            recommended_action=str(resp_raw.get("recommended_action", "")).strip(),
        ),
    )


# ---------------------------------------------------------------------------
# Generator protocol
# ---------------------------------------------------------------------------


class RuleGenerator(Protocol):
    """Each generator emits one rule's native-format text + a filename."""

    name: str
    output_subdir: str
    file_extension: str

    def render(self, rule: Rule) -> str:
        """Return the native-format text for `rule`."""
        ...

    def filename(self, rule: Rule) -> str:
        """Return the filename (without extension) for `rule` in this format."""
        ...
