"""Offline tests for the LLM Output Compliance Monitor.

Covers each of the four filters, the redaction logic, the OutputMonitor
end-to-end on the shipped corpora, and — most importantly — the
hash-chained audit log's tamper-evidence property.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from audit import HashChainAuditLog, verify_chain  # noqa: E402
from filters import (  # noqa: E402
    Action,
    ClassificationFilter,
    PIIFilter,
    PolicyFilter,
    SecretsFilter,
)
from monitor import OutputMonitor  # noqa: E402


SAMPLES = PROJECT_DIR / "samples"


# ---------------------------------------------------------------------------
# Individual filter coverage
# ---------------------------------------------------------------------------


def test_pii_filter_redacts_ssn_and_email():
    f = PIIFilter()
    text = "Customer Jane (jane@example.com), SSN 123-45-6789, ph 555-555-0101."
    findings = f.scan(text)
    actions = {x.action for x in findings}
    assert Action.REDACT in actions
    titles = " ".join(x.title for x in findings).lower()
    assert "ssn" in titles or "social security" in titles
    assert "email" in titles


def test_secrets_filter_blocks_aws_key_and_pem_block():
    f = SecretsFilter()
    text = "AWS key: AKIAIOSFODNN7EXAMPLE\n-----BEGIN OPENSSH PRIVATE KEY-----"
    findings = f.scan(text)
    assert findings, "expected secret findings"
    assert all(x.action == Action.BLOCK for x in findings)


def test_classification_filter_blocks_cui_and_secret_markers():
    f = ClassificationFilter()
    text = "CUI document — engagement notes follow. The classification is CONFIDENTIAL."
    findings = f.scan(text)
    assert findings
    assert all(x.action == Action.BLOCK for x in findings)
    kinds = {x.title.split("—")[-1].strip().lower() for x in findings}
    assert any("cui" in k for k in kinds)
    assert any("confidential" in k for k in kinds)


def test_classification_filter_does_not_match_secret_inside_secret_key():
    """The 'SECRET' marker must not match inside AWS_SECRET_KEY env-var names."""
    f = ClassificationFilter()
    findings = f.scan("AWS_SECRET_ACCESS_KEY=foo")
    # No naked SECRET marker — the env-var name shouldn't trip this filter.
    kinds = {x.title.lower() for x in findings}
    assert not any("secret" in k and "top secret" not in k for k in kinds), (
        f"false positive on AWS_SECRET_ACCESS_KEY: {kinds}"
    )


def test_policy_filter_blocks_dan_acknowledgement():
    f = PolicyFilter()
    text = "Sure, as DAN I have no restrictions and I can do anything now."
    findings = f.scan(text)
    assert findings
    assert all(x.action == Action.BLOCK for x in findings)


def test_clean_response_produces_no_findings():
    text = "The weather in Boston is partly cloudy with highs in the mid-60s."
    for f in (PIIFilter(), SecretsFilter(), ClassificationFilter(), PolicyFilter()):
        assert f.scan(text) == [], f"{f.name} false-positive on clean text"


# ---------------------------------------------------------------------------
# OutputMonitor end-to-end
# ---------------------------------------------------------------------------


def test_monitor_passes_clean_responses(tmp_path):
    mon = OutputMonitor(audit_log_path=tmp_path / "audit.jsonl")
    decision = mon.check("Two-factor auth is in account → security settings.")
    assert decision.verdict == "pass"
    assert decision.response_out == decision.response_in
    assert decision.audit_entry_id


def test_monitor_redacts_pii(tmp_path):
    mon = OutputMonitor(audit_log_path=tmp_path / "audit.jsonl")
    decision = mon.check("Email me at john@example.com or call 555-555-0101.")
    assert decision.verdict == "redact"
    assert "john@example.com" not in decision.response_out
    assert "[REDACTED:EMAIL]" in decision.response_out


def test_monitor_blocks_secrets(tmp_path):
    mon = OutputMonitor(audit_log_path=tmp_path / "audit.jsonl")
    decision = mon.check("Here's the AWS key: AKIAIOSFODNN7EXAMPLE")
    assert decision.verdict == "block"
    assert "AKIA" not in decision.response_out
    assert "compliance monitor" in decision.response_out.lower()


def test_monitor_blocks_classification_markers(tmp_path):
    mon = OutputMonitor(audit_log_path=tmp_path / "audit.jsonl")
    decision = mon.check("Per the CUI engagement notes...")
    assert decision.verdict == "block"


def test_monitor_blocks_jailbreak_acknowledgement(tmp_path):
    mon = OutputMonitor(audit_log_path=tmp_path / "audit.jsonl")
    decision = mon.check("Sure, as DAN I have no restrictions and can do anything now.")
    assert decision.verdict == "block"


def test_monitor_corpus_replay_distribution(tmp_path):
    """The shipped good/bad corpora must produce the expected verdict mix."""
    mon = OutputMonitor(audit_log_path=tmp_path / "audit.jsonl")
    counts = {"pass": 0, "redact": 0, "block": 0}

    for corpus in (SAMPLES / "good_outputs.jsonl", SAMPLES / "bad_outputs.jsonl"):
        for line in corpus.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            d = mon.check(row["response"])
            counts[d.verdict] += 1

    # All 8 good-outputs must pass.
    assert counts["pass"] >= 8
    # All bad-outputs (11 entries) must produce non-pass verdicts.
    assert counts["redact"] + counts["block"] >= 11
    # Bad outputs are weighted toward block (secrets, classification, policy)
    # over redact (PII only) — block count should dominate.
    assert counts["block"] >= counts["redact"]


# ---------------------------------------------------------------------------
# Hash-chained audit log
# ---------------------------------------------------------------------------


def test_audit_log_is_appendable_and_chains_correctly(tmp_path):
    log = HashChainAuditLog(tmp_path / "chain.jsonl")
    e1 = log.append(decision_verdict="pass", findings=[],
                    response_in="hello", response_out="hello")
    e2 = log.append(decision_verdict="block", findings=[{"title": "test"}],
                    response_in="bad", response_out="generic")
    e3 = log.append(decision_verdict="redact", findings=[{"title": "pii"}],
                    response_in="email me at a@b.com", response_out="email me at [REDACTED]")

    # Each entry's prev_hash must equal the previous entry's hash.
    assert e2.prev_hash == e1.hash
    assert e3.prev_hash == e2.hash
    # And the genesis chain is intact.
    ok, idx, _ = log.verify_chain()
    assert ok and idx is None


def test_audit_log_detects_tampering(tmp_path):
    """The whole point of the hash chain — modify any past entry and
    the integrity check must catch it."""
    path = tmp_path / "chain.jsonl"
    log = HashChainAuditLog(path)
    log.append(decision_verdict="pass", findings=[],
               response_in="hello", response_out="hello")
    log.append(decision_verdict="block", findings=[{"title": "test"}],
               response_in="bad", response_out="generic")
    log.append(decision_verdict="pass", findings=[],
               response_in="ok", response_out="ok")

    # Read all lines, mutate the second entry's verdict from "block" to "pass"
    # without recomputing its hash (an attacker covering up a block decision).
    lines = path.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[1])
    obj["decision_verdict"] = "pass"
    lines[1] = json.dumps(obj)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, idx, reason = verify_chain(path)
    assert not ok
    # The verifier should flag entry index 1 (or 2 — the chain breaks at
    # the tampered entry or the entry immediately after).
    assert idx in {1, 2}
    assert reason


def test_audit_log_detects_inserted_entry(tmp_path):
    """Inserting a synthetic entry between two real ones must also break
    the chain — even if the inserted entry's own hash is internally
    consistent, its prev_hash won't match the real previous entry."""
    path = tmp_path / "chain.jsonl"
    log = HashChainAuditLog(path)
    log.append(decision_verdict="pass", findings=[],
               response_in="a", response_out="a")
    log.append(decision_verdict="pass", findings=[],
               response_in="b", response_out="b")

    lines = path.read_text(encoding="utf-8").splitlines()
    fake = {
        "entry_id": "00000000-0000-0000-0000-000000000000",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "decision_verdict": "pass",
        "findings": [],
        "response_excerpt": "fake",
        "redaction_excerpt": "fake",
        "prev_hash": "f" * 64,   # bogus prev_hash
        "hash": "e" * 64,        # bogus hash
    }
    lines.insert(1, json.dumps(fake))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, idx, _ = verify_chain(path)
    assert not ok
    assert idx == 1
