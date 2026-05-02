"""Offline tests for the SIEM correlation-rule generator.

Validates rule loading, per-generator output shape, and the end-to-end
generator CLI. No API key, no network — pure offline.
"""

from __future__ import annotations

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
    Rule,
    SigmaGenerator,
    SplunkESGenerator,
    load_rule,
    load_rules,
)

TEMPLATES = PROJECT_DIR / "templates"


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------


def test_templates_load_into_rule_objects():
    rules = load_rules(TEMPLATES)
    assert len(rules) >= 8, "expected at least 8 starter rules"
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)), "rule IDs must be unique"
    # Every rule must declare its event source and severity.
    for r in rules:
        assert r.event_type, f"{r.id} missing event_type"
        assert r.severity in {"low", "medium", "high", "critical"}
        assert r.owasp_llm.startswith("LLM"), f"{r.id} missing OWASP mapping"


def test_rules_cover_target_event_types():
    rules = load_rules(TEMPLATES)
    event_types = {r.event_type for r in rules}
    # MVP must cover all three Project 1/2/3 event shapes.
    assert {"ai_prompt_injection", "ai_red_team_finding", "ai_rag_finding"}.issubset(event_types)


# ---------------------------------------------------------------------------
# Per-generator output shape
# ---------------------------------------------------------------------------


def test_splunk_generator_emits_well_formed_stanza():
    rule = load_rule(TEMPLATES / "AIPI-001-malicious-prompt-injection.yaml")
    out = SplunkESGenerator().render(rule)
    # Stanza header must be the rule name in brackets.
    assert f"[{rule.name}]" in out
    assert "search = " in out
    assert "action.notable = 1" in out
    assert "verdict=\"malicious\"" in out
    # Stanza must reference the source index + sourcetype.
    assert f"index={rule.source_index}" in out
    assert f'sourcetype="{rule.sourcetype}"' in out


def test_sigma_generator_emits_parseable_yaml():
    rule = load_rule(TEMPLATES / "AIPI-001-malicious-prompt-injection.yaml")
    out = SigmaGenerator().render(rule)
    # Must be valid YAML.
    parsed = pyyaml.safe_load(out)
    assert parsed["title"] == rule.name
    assert parsed["level"] == rule.severity
    assert "selection" in parsed["detection"]
    assert parsed["detection"]["selection"]["verdict"] == "malicious"
    # Logsource must carry the right service.
    assert parsed["logsource"]["product"] == "aisec"
    assert parsed["logsource"]["service"] == "prompt_injection"


def test_xsiam_generator_emits_xql_with_metadata_header():
    rule = load_rule(TEMPLATES / "AIRT-001-red-team-fail-finding.yaml")
    out = CortexXSIAMGenerator().render(rule)
    # Metadata as XQL comments.
    assert f"// rule_id: {rule.id}" in out
    assert f"// owasp: {rule.owasp_llm}" in out
    # XQL body.
    assert "dataset = aisec_red_team_finding" in out
    assert "| filter cim_eventtype" in out
    assert "| comp count()" in out
    assert "| filter event_count >= 1" in out


def test_xsiam_generator_handles_in_operator():
    """A rule using `operator: in` should produce XQL with `field in (...)`."""
    # Synthesize a Rule via the loader's path with a dict that uses 'in' op.
    from rules.base import _to_rule  # noqa
    raw = {
        "id": "TST-001", "name": "Test In Op", "description": "test",
        "sourcetype": "aisec:test", "event_type": "ai_test",
        "severity": "medium", "owasp_llm": "LLM01", "airmf": "MEASURE 2.7",
        "mitre_atlas": [],
        "condition": {"field": "verdict", "operator": "in",
                      "value": ["malicious", "suspicious"]},
        "aggregation": {"group_by": ["user"], "threshold_count": 1, "window": "1h"},
        "response": {"notable_event": True, "drilldown_field": "user",
                     "recommended_action": "test"},
    }
    rule = _to_rule(raw)
    out = CortexXSIAMGenerator().render(rule)
    assert 'verdict in ("malicious", "suspicious")' in out


# ---------------------------------------------------------------------------
# End-to-end CLI
# ---------------------------------------------------------------------------


def test_generator_writes_one_file_per_rule_per_platform(tmp_path):
    rules = load_rules(TEMPLATES)
    generators = [SplunkESGenerator(), SigmaGenerator(), CortexXSIAMGenerator()]
    out = tmp_path / "out"
    n = emit_all(rules, generators, out)
    expected = len(rules) * len(generators)
    assert n == expected, f"expected {expected} files, got {n}"
    # Every per-platform directory must contain a file per rule.
    for gen in generators:
        sub = out / gen.output_subdir
        files = list(sub.glob(f"*{gen.file_extension}"))
        assert len(files) == len(rules), (
            f"{gen.name} produced {len(files)} files for {len(rules)} rules"
        )


def test_coverage_map_lists_every_rule(tmp_path):
    rules = load_rules(TEMPLATES)
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    path = write_coverage_map(rules, out)
    text = path.read_text(encoding="utf-8")
    # Every rule ID must appear in the rendered map.
    for r in rules:
        assert r.id in text, f"{r.id} missing from coverage map"
    # Coverage map must include OWASP and AI RMF rollups.
    assert "OWASP LLM Top 10" in text
    assert "AI RMF" in text
