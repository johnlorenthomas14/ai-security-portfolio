"""Offline tests for the RAG security auditor.

All tests run against the shipped demo corpus — no API key, no network.
CI gate: every push runs these on Python 3.11 and 3.12.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from auditor import load_corpus, scan_corpus, summarize  # noqa: E402
from report import write_reports  # noqa: E402
from scanners import (  # noqa: E402
    Document,
    IndirectInjectionScanner,
    PIIScanner,
    SecretsScanner,
    SensitivityScanner,
)

DEMO_CORPUS = PROJECT_DIR / "corpus" / "demo"


# ---------------------------------------------------------------------------
# Corpus loading
# ---------------------------------------------------------------------------


def test_demo_corpus_loads():
    docs = load_corpus(DEMO_CORPUS)
    assert len(docs) >= 5, "demo corpus should ship at least 5 documents"
    paths = {d.relative_path for d in docs}
    assert any("poisoned-faq" in p for p in paths)
    assert any("dev-runbook" in p for p in paths)
    assert any("cui-program-notes" in p for p in paths)


# ---------------------------------------------------------------------------
# Individual scanners against known-bad documents
# ---------------------------------------------------------------------------


def _doc(path: Path, root: Path = DEMO_CORPUS) -> Document:
    return Document(path=path, text=path.read_text(encoding="utf-8"),
                    relative_path=str(path.relative_to(root)))


def test_injection_scanner_flags_poisoned_faq():
    findings = IndirectInjectionScanner().scan(_doc(DEMO_CORPUS / "02-poisoned-faq.md"))
    assert findings, "poisoned FAQ must be flagged by injection scanner"
    assert any("LLM01" in f.owasp_category for f in findings)


def test_pii_scanner_flags_customer_feedback():
    findings = PIIScanner().scan(_doc(DEMO_CORPUS / "03-customer-feedback.md"))
    assert findings, "customer-feedback document must produce PII findings"
    kinds = {f.title.split("—")[-1].strip() for f in findings}
    # Should have at least email and SSN findings.
    assert any("email" in k for k in kinds)
    assert any("ssn" in k for k in kinds)


def test_secrets_scanner_flags_dev_runbook():
    findings = SecretsScanner().scan(_doc(DEMO_CORPUS / "04-dev-runbook.md"))
    assert findings, "dev runbook must produce secret findings"
    titles = {f.title for f in findings}
    # AWS key + GitHub token + Anthropic key + PEM should all fire.
    assert any("AWS" in t for t in titles)
    assert any("GitHub" in t for t in titles)
    # Anthropic OR OpenAI key should fire.
    assert any("Anthropic" in t or "OpenAI" in t for t in titles)
    # PEM block.
    assert any("Private key" in t for t in titles)


def test_sensitivity_scanner_flags_cui_doc():
    findings = SensitivityScanner().scan(_doc(DEMO_CORPUS / "05-cui-program-notes.md"))
    assert findings, "CUI document must trip sensitivity scanner"
    assert any("cui" in f.finding_id.lower() for f in findings)


def test_clean_documents_produce_no_findings():
    """Documents with no PII / secrets / markers / injection payloads must
    return empty for every scanner."""
    clean = _doc(DEMO_CORPUS / "06-product-spec.md")
    for scanner in (IndirectInjectionScanner(), PIIScanner(), SecretsScanner(), SensitivityScanner()):
        assert scanner.scan(clean) == [], (
            f"{scanner.name} produced findings on a clean document"
        )


# ---------------------------------------------------------------------------
# End-to-end run
# ---------------------------------------------------------------------------


def test_end_to_end_audit_on_demo_corpus():
    docs = load_corpus(DEMO_CORPUS)
    findings = scan_corpus(docs)
    summary = summarize(findings, len(docs))

    assert summary["n_findings"] >= 8, (
        "demo corpus should produce a substantial number of findings"
    )
    # Severity rollup must include at least one critical (PEM block) finding.
    assert summary["by_severity"].get("critical", 0) >= 1

    # Every finding must carry the CIM fields needed for Splunk ingestion.
    for f in findings:
        assert f["cim_eventtype"] == "ai_rag_finding"
        assert f["signature"] == "rag_security_auditor"
        assert f["severity"] in {"low", "medium", "high", "critical"}


def test_report_writers_produce_valid_outputs(tmp_path):
    docs = load_corpus(DEMO_CORPUS)
    findings = scan_corpus(docs)
    summary = summarize(findings, len(docs))

    out = tmp_path / "out"
    write_reports(
        findings=findings, summary=summary, corpus_root=DEMO_CORPUS, out_dir=out,
    )

    json_path = out / "findings.json"
    md_path = out / "audit_report.md"
    assert json_path.exists()
    assert md_path.exists()

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert isinstance(data["findings"], list)
    assert data["run"]["summary"]["n_findings"] == len(findings)

    md = md_path.read_text(encoding="utf-8")
    assert "RAG Pipeline Security Audit" in md
    assert "OWASP" in md
    assert "AI RMF" in md
    assert "Executive summary" in md
