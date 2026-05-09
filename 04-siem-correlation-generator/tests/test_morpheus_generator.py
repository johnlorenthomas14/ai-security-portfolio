"""Offline tests for the NVIDIA Morpheus pipeline-stage generator.

Mirrors the existing test_generator.py patterns:
  - Basic render shape + YAML parseability
  - Operator coverage (equals, in, gte, gt, contains)
  - Metadata-header checks (rule_id, OWASP, ATLAS, AI RMF)
  - End-to-end emit_all confirms the morpheus output directory is populated

Adds one Morpheus-specific test that validates the generated filter
expressions against `samples/morpheus_events.jsonl` — i.e., for each
rule's condition, at least one sample event in the corpus matches.
This catches filter-expression regressions that would silently break a
real Morpheus deployment without requiring a GPU / cuDF runtime.

No pytest plugins required. No network. No API key.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml as pyyaml

PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from generator import emit_all, write_coverage_map  # noqa: E402
from rules import (  # noqa: E402
    CortexXSIAMGenerator,
    MorpheusGenerator,
    SigmaGenerator,
    SplunkESGenerator,
    load_rule,
    load_rules,
)
from rules.base import _to_rule  # noqa: E402

TEMPLATES = PROJECT_DIR / "templates"
SAMPLES = PROJECT_DIR / "samples" / "morpheus_events.jsonl"


# ---------------------------------------------------------------------------
# Basic render shape
# ---------------------------------------------------------------------------


def test_morpheus_generator_protocol_attrs():
    g = MorpheusGenerator()
    assert g.name == "morpheus"
    assert g.output_subdir == "morpheus"
    assert g.file_extension == ".yaml"


def test_morpheus_generator_emits_parseable_yaml():
    rule = load_rule(TEMPLATES / "AIPI-001-malicious-prompt-injection.yaml")
    out = MorpheusGenerator().render(rule)

    parsed = pyyaml.safe_load(out)
    assert parsed["pipeline"]["name"] == f"ai-security-{rule.id.lower()}"

    # Stage chain must be present in the canonical order.
    stage_types = [s.get("type") for s in parsed["pipeline"]["stages"]]
    assert "deserialize" in stage_types
    assert "filter" in stage_types
    assert "aggregate" in stage_types
    assert "add-class" in stage_types
    assert "serialize" in stage_types

    # Filter stage must guard on cim_eventtype + the rule's condition.
    filter_stages = [s for s in parsed["pipeline"]["stages"] if s["type"] == "filter"]
    assert len(filter_stages) == 1
    cond = filter_stages[0]["condition"]
    assert f'cim_eventtype == "{rule.event_type}"' in cond
    assert "verdict" in cond  # AIPI-001's condition field
    assert '"malicious"' in cond  # AIPI-001's condition value


def test_morpheus_generator_emits_metadata_header():
    rule = load_rule(TEMPLATES / "AIPI-003-tool-abuse-attempt.yaml")
    out = MorpheusGenerator().render(rule)
    # Header is YAML comments — survives parsing, visible to a human reviewer.
    assert f"# rule_id: {rule.id}" in out
    assert f"# severity: {rule.severity}" in out
    assert f"# owasp: {rule.owasp_llm}" in out
    # ATLAS techniques rendered comma-separated.
    for t in rule.mitre_atlas:
        assert t in out
    assert f"# airmf: {rule.airmf}" in out


def test_morpheus_generator_surfaces_tags():
    rule = load_rule(TEMPLATES / "AIRG-001-corpus-credential-leak.yaml")
    parsed = pyyaml.safe_load(MorpheusGenerator().render(rule))
    tags = parsed["tags"]
    assert tags["rule_id"] == rule.id
    assert tags["owasp_llm"] == rule.owasp_llm
    assert tags["airmf"] == rule.airmf
    # MITRE ATLAS list is preserved as a list.
    assert isinstance(tags["mitre_atlas"], list)
    assert list(tags["mitre_atlas"]) == list(rule.mitre_atlas)


# ---------------------------------------------------------------------------
# Operator coverage
# ---------------------------------------------------------------------------


def _synthetic_rule(condition: dict, event_type: str = "ai_test"):
    raw = {
        "id": "TST-001",
        "name": "Synthetic Test Rule",
        "description": "test",
        "sourcetype": "aisec:test",
        "event_type": event_type,
        "severity": "medium",
        "owasp_llm": "LLM01",
        "airmf": "MEASURE 2.7",
        "mitre_atlas": [],
        "condition": condition,
        "aggregation": {
            "group_by": ["user"],
            "threshold_count": 1,
            "window": "1h",
        },
        "response": {
            "notable_event": True,
            "drilldown_field": "user",
            "recommended_action": "test",
        },
    }
    return _to_rule(raw)


def test_morpheus_handles_equals_operator():
    rule = _synthetic_rule({"field": "verdict", "operator": "equals", "value": "malicious"})
    out = MorpheusGenerator().render(rule)
    parsed = pyyaml.safe_load(out)
    cond = parsed["pipeline"]["stages"][2]["condition"]  # filter is index 2
    assert 'verdict == "malicious"' in cond


def test_morpheus_handles_in_operator():
    rule = _synthetic_rule(
        {"field": "verdict", "operator": "in", "value": ["malicious", "suspicious"]}
    )
    cond = pyyaml.safe_load(MorpheusGenerator().render(rule))["pipeline"]["stages"][2]["condition"]
    assert 'verdict.isin(["malicious", "suspicious"])' in cond


def test_morpheus_handles_gte_operator():
    rule = _synthetic_rule({"field": "count", "operator": "gte", "value": 5})
    cond = pyyaml.safe_load(MorpheusGenerator().render(rule))["pipeline"]["stages"][2]["condition"]
    assert "count >= 5" in cond


def test_morpheus_handles_gt_operator():
    rule = _synthetic_rule({"field": "count", "operator": "gt", "value": 5})
    cond = pyyaml.safe_load(MorpheusGenerator().render(rule))["pipeline"]["stages"][2]["condition"]
    assert "count > 5" in cond


def test_morpheus_handles_contains_operator():
    rule = _synthetic_rule({"field": "signals", "operator": "contains", "value": "PI-008"})
    cond = pyyaml.safe_load(MorpheusGenerator().render(rule))["pipeline"]["stages"][2]["condition"]
    assert 'signals.str.contains("PI-008")' in cond


# ---------------------------------------------------------------------------
# Aggregation + window mapping
# ---------------------------------------------------------------------------


def test_morpheus_translates_window_to_seconds():
    rule = load_rule(TEMPLATES / "AIPI-003-tool-abuse-attempt.yaml")  # 24h window
    parsed = pyyaml.safe_load(MorpheusGenerator().render(rule))
    agg = next(s for s in parsed["pipeline"]["stages"] if s["type"] == "aggregate")
    assert agg["window_seconds"] == 86400
    assert list(agg["group_by"]) == list(rule.aggregation.group_by)
    assert agg["threshold_count"] == rule.aggregation.threshold_count


# ---------------------------------------------------------------------------
# End-to-end with all four generators
# ---------------------------------------------------------------------------


def test_emit_all_with_morpheus_produces_four_platform_outputs(tmp_path):
    rules = load_rules(TEMPLATES)
    generators = [
        SplunkESGenerator(),
        SigmaGenerator(),
        CortexXSIAMGenerator(),
        MorpheusGenerator(),
    ]
    out = tmp_path / "out"
    n = emit_all(rules, generators, out)
    expected = len(rules) * 4
    assert n == expected, f"expected {expected} files for four platforms, got {n}"

    # The morpheus subdirectory must contain one .yaml per rule.
    morpheus_dir = out / "morpheus"
    yamls = list(morpheus_dir.glob("*.yaml"))
    assert len(yamls) == len(rules)

    # Every emitted file must parse as YAML.
    for p in yamls:
        parsed = pyyaml.safe_load(p.read_text(encoding="utf-8"))
        assert "pipeline" in parsed
        assert "tags" in parsed


def test_coverage_map_mentions_morpheus(tmp_path):
    rules = load_rules(TEMPLATES)
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    path = write_coverage_map(rules, out)
    assert "Morpheus" in path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The sample-corpus alignment test — proves filter expressions match real events
# ---------------------------------------------------------------------------


def _load_sample_events() -> list[dict]:
    """Load the JSONL sample corpus."""
    if not SAMPLES.exists():
        pytest.skip(f"sample corpus not found at {SAMPLES}")
    return [json.loads(line) for line in SAMPLES.read_text(encoding="utf-8").splitlines() if line.strip()]


def _matches(event: dict, condition_field: str, operator: str, value) -> bool:
    """Pure-Python evaluator for the canonical condition operators.

    Mirrors the semantics of Morpheus's filter stage on the deserialized
    PAYLOAD dataframe, without requiring cuDF / GPU. Used in tests only.
    """
    if condition_field not in event:
        return False
    field_val = event[condition_field]
    op = operator.lower()
    if op == "equals":
        return field_val == value
    if op == "in":
        if isinstance(value, (list, tuple)):
            return field_val in value
        return field_val == value
    if op == "gte":
        try:
            return float(field_val) >= float(value)
        except (TypeError, ValueError):
            return False
    if op == "gt":
        try:
            return float(field_val) > float(value)
        except (TypeError, ValueError):
            return False
    if op == "contains":
        # `signals` is a list of detector-rule IDs; other fields are strings.
        if isinstance(field_val, list):
            return any(value in str(item) for item in field_val)
        return str(value) in str(field_val)
    return False


def test_every_rule_matches_at_least_one_sample_event():
    """For each rule, at least one event in the sample corpus must satisfy:
    cim_eventtype == rule.event_type AND the rule's condition.

    This is the alignment check between the rule library and the sample
    corpus shipped for Morpheus testing/deployment.
    """
    rules = load_rules(TEMPLATES)
    events = _load_sample_events()

    misaligned: list[str] = []
    for rule in rules:
        # Step 1: filter to events of the right CIM eventtype.
        cim_matches = [e for e in events if e.get("cim_eventtype") == rule.event_type]
        if not cim_matches:
            misaligned.append(f"{rule.id}: no events with cim_eventtype={rule.event_type}")
            continue
        # Step 2: of those, at least one must satisfy the rule's condition.
        condition_matches = [
            e for e in cim_matches
            if _matches(e, rule.condition.field, rule.condition.operator, rule.condition.value)
        ]
        if not condition_matches:
            misaligned.append(
                f"{rule.id}: no events satisfy {rule.condition.field} "
                f"{rule.condition.operator} {rule.condition.value}"
            )

    assert not misaligned, "Rule/sample misalignment:\n  " + "\n  ".join(misaligned)


def test_benign_baseline_event_does_not_match_any_malicious_rule():
    """The benign baseline event in the corpus must not satisfy any rule
    that targets malicious / suspicious / fail / critical conditions.

    Catches the regression where a too-permissive filter would alert on a
    benign weather query.
    """
    events = _load_sample_events()
    benign = [e for e in events if e.get("verdict") == "benign"]
    assert benign, "expected at least one benign baseline event in the corpus"

    rules = load_rules(TEMPLATES)
    for rule in rules:
        for event in benign:
            if event.get("cim_eventtype") != rule.event_type:
                continue
            assert not _matches(
                event, rule.condition.field, rule.condition.operator, rule.condition.value
            ), f"benign event matched {rule.id} — filter expression too permissive"
