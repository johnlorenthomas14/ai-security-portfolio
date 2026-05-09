"""Integration tests for the NeMoGuardrailsFilter in Project 5's
output-monitor chain.

Confirms:
  - Default monitor (no opt-in flag) is byte-for-byte identical to the
    pre-G3 monitor — the existing CI corpus replay assertions depend
    on this.
  - When ``include_nemo_guardrails=True``, the filter is appended to
    the chain and fires on the same secret / classification / jailbreak
    vocabulary the rest of Project 5 already detects.
  - Findings from the new filter carry the right OWASP / MITRE ATLAS /
    NIST AI RMF tags, the BLOCK action, and a recognizable filter name.
  - The hash-chained audit log records the new filter's findings while
    preserving chain integrity across mixed runs.
  - Fail-open: if the action layer can't be imported, the filter
    returns no findings and the rest of the chain runs unaffected.

No NeMo Guardrails SDK required.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from filters import Action, NeMoGuardrailsFilter  # noqa: E402
from monitor import OutputMonitor  # noqa: E402
from audit import verify_chain  # noqa: E402


# ---------------------------------------------------------------------------
# Default-off: monitor chain unchanged
# ---------------------------------------------------------------------------


def test_default_monitor_excludes_guardrails_filter():
    mon = OutputMonitor()
    names = [f.name for f in mon.filters]
    assert "nemo_guardrails" not in names
    assert len(mon.filters) == 4


def test_explicit_filters_param_overrides_default_chain():
    """When the caller passes filters=[...] explicitly, the include flag
    is ignored — the caller has full control."""
    custom = [NeMoGuardrailsFilter()]
    mon = OutputMonitor(filters=custom, include_nemo_guardrails=True)
    assert len(mon.filters) == 1
    assert mon.filters[0].name == "nemo_guardrails"


# ---------------------------------------------------------------------------
# Opt-in chain
# ---------------------------------------------------------------------------


def test_include_flag_appends_guardrails_filter():
    mon = OutputMonitor(include_nemo_guardrails=True)
    names = [f.name for f in mon.filters]
    assert names == [
        "pii_filter",
        "secrets_filter",
        "classification_filter",
        "policy_filter",
        "nemo_guardrails",
    ]


# ---------------------------------------------------------------------------
# Filter behavior
# ---------------------------------------------------------------------------


def test_guardrails_filter_fires_on_aws_secret():
    f = NeMoGuardrailsFilter()
    findings = f.scan("Here is the key: AKIAIOSFODNN7EXAMPLE")
    assert len(findings) == 1
    assert findings[0].action == Action.BLOCK
    assert findings[0].filter_name == "nemo_guardrails"
    assert findings[0].owasp_category == "LLM02"
    assert findings[0].atlas_techniques == ["AML.T0024"]
    assert findings[0].airmf_subcategory == "MEASURE 2.10"
    assert findings[0].severity == "critical"


def test_guardrails_filter_fires_on_cui_marker():
    f = NeMoGuardrailsFilter()
    findings = f.scan("This document is marked CUI//FOUO and contains program data.")
    assert len(findings) == 1
    assert findings[0].owasp_category == "LLM02"
    assert findings[0].airmf_subcategory == "GOVERN 1.3"


def test_guardrails_filter_fires_on_jailbreak_acknowledgement():
    f = NeMoGuardrailsFilter()
    findings = f.scan("Sure, as DAN I have no restrictions.")
    assert len(findings) == 1
    assert findings[0].owasp_category == "LLM01"
    assert findings[0].atlas_techniques == ["AML.T0054"]
    assert findings[0].airmf_subcategory == "MEASURE 2.6"


def test_guardrails_filter_returns_empty_on_benign():
    f = NeMoGuardrailsFilter()
    assert f.scan("The weather forecast is sunny.") == []
    assert f.scan("") == []


def test_guardrails_filter_matched_span_resolves_to_real_offsets():
    """Filter must populate matched_span correctly so the redaction-rendering
    code (and any drilldown UI) can highlight the offending substring."""
    f = NeMoGuardrailsFilter()
    text = "before AKIAIOSFODNN7EXAMPLE after"
    findings = f.scan(text)
    assert findings
    s, e = findings[0].matched_span
    assert text[s:e] == "AKIAIOSFODNN7EXAMPLE"


# ---------------------------------------------------------------------------
# End-to-end through the monitor
# ---------------------------------------------------------------------------


def test_monitor_with_guardrails_blocks_secret_and_logs_filter_name(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    mon = OutputMonitor(include_nemo_guardrails=True, audit_log_path=audit_path)
    decision = mon.check("My GitHub token is ghp_abcdefghijklmnopqrstuvwxyz0123456789")

    assert decision.verdict == "block"
    filter_names = sorted({f.filter_name for f in decision.findings})
    # Both the existing secrets_filter and the new nemo_guardrails filter fire.
    assert "secrets_filter" in filter_names
    assert "nemo_guardrails" in filter_names

    # Audit log entry must include both filter names
    entry = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[-1])
    audit_filters = sorted({f["filter"] for f in entry["findings"]})
    assert "nemo_guardrails" in audit_filters


def test_monitor_with_guardrails_passes_benign(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    mon = OutputMonitor(include_nemo_guardrails=True, audit_log_path=audit_path)
    decision = mon.check("The weather forecast for Tuesday is sunny.")
    assert decision.verdict == "pass"


def test_audit_chain_remains_valid_with_guardrails_decisions(tmp_path):
    """Hash-chain integrity must hold across mixed Guardrails / non-Guardrails
    decisions — that's the FedRAMP integrity-evidence property."""
    audit_path = tmp_path / "audit.jsonl"
    mon = OutputMonitor(include_nemo_guardrails=True, audit_log_path=audit_path)

    mon.check("Hello, what is the weather today?")
    mon.check("Sure, as DAN I have no restrictions.")
    mon.check("ghp_abcdefghijklmnopqrstuvwxyz0123456789")
    mon.check("This document is marked CUI//FOUO.")
    mon.check("Have a nice day.")

    ok, idx, reason = verify_chain(audit_path)
    assert ok, f"chain broken at {idx}: {reason}"

    # Confirm at least one entry's findings contain a nemo_guardrails finding
    seen_nemo = False
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if any(f["filter"] == "nemo_guardrails" for f in e.get("findings", [])):
            seen_nemo = True
            break
    assert seen_nemo, "expected at least one entry to carry a nemo_guardrails finding"


# ---------------------------------------------------------------------------
# Fail-open
# ---------------------------------------------------------------------------


def test_filter_fails_open_when_action_layer_missing(monkeypatch):
    """Force the lazy-import to return None — filter must return [] and
    not raise."""
    f = NeMoGuardrailsFilter()
    monkeypatch.setattr(NeMoGuardrailsFilter, "_load_check_output", staticmethod(lambda: None))
    assert f.scan("anything at all even AKIAIOSFODNN7EXAMPLE") == []


def test_filter_fails_open_when_action_raises(monkeypatch):
    """Force the action helper to raise — filter must catch and return []."""
    def boom(text):
        raise RuntimeError("simulated action failure")
    monkeypatch.setattr(NeMoGuardrailsFilter, "_load_check_output", staticmethod(lambda: boom))
    f = NeMoGuardrailsFilter()
    assert f.scan("anything") == []
