"""Offline tests for the Threat Intelligence Summarizer.

Coverage:
  - STIX bundle loader produces an indexed bundle from real shipped samples.
  - Citation verifier accepts real bundle IDs and rejects hallucinated ones.
  - Stub client produces a brief whose every citation resolves.
  - Notable emitter produces one event per indicator with linked refs.
  - End-to-end summarizer (offline mode) writes briefs + notables.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from brief import BriefGenerator, StubClient, verify_citations  # noqa: E402
from feed import iter_bundles, load_bundle  # noqa: E402
from notables import emit_notables  # noqa: E402
from summarizer import main as summarizer_main  # noqa: E402


SAMPLES = PROJECT_DIR / "samples" / "stix_bundles"
PHISH_BUNDLE = SAMPLES / "01-phishing-campaign.json"
CVE_BUNDLE = SAMPLES / "02-cve-advisory.json"


# ---------------------------------------------------------------------------
# STIX loader
# ---------------------------------------------------------------------------


def test_loader_indexes_phishing_bundle():
    bundle = load_bundle(PHISH_BUNDLE)
    assert bundle.spec_version == "2.1"
    assert len(bundle) >= 13, "phishing bundle should have at least 13 objects"
    # Specific objects we cite from in tests.
    assert bundle.has("campaign--apt-finsector-2026q1")
    assert bundle.has("threat-actor--mimicry-collective")
    assert bundle.has("malware--credstealer-q1-2026")
    assert bundle.has("indicator--phish-domain-acme-sso")


def test_iter_bundles_yields_both_samples():
    paths = [p.name for p, _ in iter_bundles(SAMPLES)]
    assert "01-phishing-campaign.json" in paths
    assert "02-cve-advisory.json" in paths


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


def test_verifier_accepts_resolved_citations():
    bundle = load_bundle(PHISH_BUNDLE)
    brief = (
        "The campaign [campaign--apt-finsector-2026q1] is attributed to "
        "[threat-actor--mimicry-collective] and uses "
        "[malware--credstealer-q1-2026]."
    )
    findings = verify_citations(brief, bundle)
    assert len(findings) == 3
    assert all(f.resolved for f in findings)


def test_verifier_rejects_hallucinated_citations():
    bundle = load_bundle(PHISH_BUNDLE)
    brief = (
        "The campaign [campaign--apt-finsector-2026q1] is attributed to "
        "[threat-actor--made-up-actor-not-in-bundle] and uses "
        "[malware--also-fake]."
    )
    findings = verify_citations(brief, bundle)
    resolved = [f for f in findings if f.resolved]
    halluc = [f for f in findings if not f.resolved]
    assert len(resolved) == 1
    assert len(halluc) == 2
    assert {f.citation for f in halluc} == {
        "threat-actor--made-up-actor-not-in-bundle",
        "malware--also-fake",
    }


def test_verifier_counts_repeated_citations():
    bundle = load_bundle(PHISH_BUNDLE)
    brief = (
        "First mention [indicator--phish-domain-acme-sso]. "
        "Second mention of the same domain [indicator--phish-domain-acme-sso]."
    )
    findings = verify_citations(brief, bundle)
    assert len(findings) == 1
    assert findings[0].occurrences == 2
    assert findings[0].resolved


# ---------------------------------------------------------------------------
# Stub client
# ---------------------------------------------------------------------------


def test_stub_brief_uses_only_real_citations():
    """The stub client constructs the brief from real bundle objects, so
    every citation it produces must resolve."""
    bundle = load_bundle(PHISH_BUNDLE)
    md = StubClient().generate_brief(bundle)
    findings = verify_citations(md, bundle)
    halluc = [f for f in findings if not f.resolved]
    assert halluc == [], (
        f"stub client must never hallucinate; got: "
        f"{[f.citation for f in halluc]}"
    )


def test_stub_brief_has_canonical_sections():
    bundle = load_bundle(PHISH_BUNDLE)
    md = StubClient().generate_brief(bundle)
    assert "# Threat Intel Brief" in md
    assert "## Executive summary" in md
    assert "## Indicators of compromise" in md
    assert "## TTPs (MITRE ATT&CK)" in md
    assert "## Recommended actions" in md


# ---------------------------------------------------------------------------
# BriefGenerator (offline mode)
# ---------------------------------------------------------------------------


def test_brief_generator_offline_produces_clean_brief():
    bundle = load_bundle(CVE_BUNDLE)
    brief = BriefGenerator(offline=True).generate(bundle)
    assert brief.generator == "stub"
    assert brief.citation_summary["n_hallucinated"] == 0
    assert brief.citation_summary["n_resolved"] >= 4
    # Specific bundle IDs that should appear in the cited brief.
    cited_ids = {f.citation for f in brief.citations}
    assert "vulnerability--cve-2026-12345" in cited_ids
    assert "indicator--exploit-payload-signature" in cited_ids


# ---------------------------------------------------------------------------
# Notable emitter
# ---------------------------------------------------------------------------


def test_notable_emitter_one_event_per_indicator():
    bundle = load_bundle(PHISH_BUNDLE)
    events = emit_notables(bundle)
    indicators = bundle.by_type("indicator")
    assert len(events) == len(indicators)
    # Every event has the CIM eventtype and signature.
    for e in events:
        assert e["cim_eventtype"] == "ai_threat_intel_indicator"
        assert e["signature"] == "threat_intel_summarizer"
        assert e["source_bundle"] == bundle.bundle_id


def test_notable_emitter_classifies_indicator_types():
    bundle = load_bundle(PHISH_BUNDLE)
    events = emit_notables(bundle)
    by_type = {e["indicator_id"]: e["indicator_type"] for e in events}
    assert by_type["indicator--phish-domain-acme-sso"] == "domain"
    assert by_type["indicator--c2-exfil-endpoint"] == "url"
    assert by_type["indicator--phish-page-sha256"] == "file_hash"


def test_notable_emitter_extracts_observable_values():
    bundle = load_bundle(PHISH_BUNDLE)
    events = emit_notables(bundle)
    domain_event = next(
        e for e in events if e["indicator_id"] == "indicator--phish-domain-acme-sso"
    )
    assert "acme-sso.example-attacker.com" in domain_event["indicator_values"]


def test_notable_emitter_links_indicators_to_related_objects():
    bundle = load_bundle(PHISH_BUNDLE)
    events = emit_notables(bundle)
    domain_event = next(
        e for e in events if e["indicator_id"] == "indicator--phish-domain-acme-sso"
    )
    # The phishing-domain indicator should be linked to the malware via the
    # `indicator-indicates-malware` relationship.
    assert "malware--credstealer-q1-2026" in domain_event["linked_to"]


# ---------------------------------------------------------------------------
# End-to-end summarizer CLI
# ---------------------------------------------------------------------------


def test_summarizer_cli_offline_produces_briefs_and_notables(tmp_path, monkeypatch):
    monkeypatch.chdir(PROJECT_DIR)
    out_dir = tmp_path / "out"
    rc = summarizer_main([
        "--bundles", str(SAMPLES),
        "--output", str(out_dir),
        "--offline",
        "--quiet",
    ])
    assert rc == 0, "stub-mode brief should produce zero hallucinations and exit 0"

    # Two briefs, two notable files, one citation audit.
    assert (out_dir / "briefs" / "01-phishing-campaign.md").exists()
    assert (out_dir / "briefs" / "02-cve-advisory.md").exists()
    assert (out_dir / "notables" / "01-phishing-campaign.json").exists()
    assert (out_dir / "notables" / "02-cve-advisory.json").exists()
    audit = json.loads((out_dir / "citation_audit.json").read_text(encoding="utf-8"))
    assert audit["bundles_processed"] == 2
    assert audit["total_hallucinations"] == 0
