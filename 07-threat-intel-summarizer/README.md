# 07 — Adaptive Threat Intelligence Summarizer

[![CI](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml/badge.svg)](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![STIX 2.1](https://img.shields.io/badge/STIX-2.1-blue.svg)](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
[![Citation-verified](https://img.shields.io/badge/citations-verified-brightgreen.svg)](#the-citation-verifier-the-differentiator)

> **Reads STIX 2.1 threat-intel bundles, asks Claude to produce an
> analyst-readable brief with explicit citations to STIX object IDs,
> verifies that every citation resolves to a real object (catching
> hallucinated references), and emits both the markdown brief and
> CIM-shaped Splunk notable events for the indicators contained in
> the bundle.** The first project in the portfolio where Claude is
> *the producer of user-visible content* — and the differentiator is
> the citation verifier that gates the brief before it reaches an
> analyst.

**Status:** Working MVP. Ships with two hand-crafted STIX 2.1 bundles
(phishing campaign + CVE advisory), a stub client for offline /
no-API-key operation, a citation verifier with positive and negative
test paths, a 14-test pytest suite, and a CI job that runs the full
pipeline offline and asserts zero hallucinated citations.

## Demo

[![asciicast](https://asciinema.org/a/3ZcGr9bfaIBTyJRa.svg)](https://asciinema.org/a/3ZcGr9bfaIBTyJRa)

90-second walkthrough — the shipped STIX bundles, a bundle's object
types, the summarizer running offline with the stub client (zero
hallucinations across 13 citations on both bundles), the generated
analyst brief with every claim cited to a real STIX object ID, the
emitted Splunk notable events with `linked_to` cross-references derived
from STIX relationships, the citation audit, and the pytest suite.
Click the cast above to play, or run it yourself:

```bash
cd 07-threat-intel-summarizer
./demo.sh
```

## Threat model

| | |
|---|---|
| **Attacker capability** | None directly — this project is on the defensive side, producing intel briefs for SOC analysts. The relevant attack surface is *Claude itself*: an LLM producing analyst-facing content can hallucinate facts, invent indicator IDs, or misattribute campaigns. Without verification, those hallucinations propagate into SOC decisions. |
| **Target asset** | The trustworthiness of the analyst brief and the integrity of any downstream actions (block lists, correlation searches, notable events) the brief informs. |
| **In scope** | STIX 2.1 bundle parsing; LLM-generated brief synthesis with explicit citation discipline; citation verification (the security control); CIM-shaped Splunk notable emission for each indicator in the bundle. |
| **Out of scope (MVP)** | Live TAXII 2.x server polling — current MVP reads bundles from disk; a TAXII client is the obvious roadmap addition. Indicator deduplication / clustering across many bundles. Adaptive prompt-tuning per analyst preference. Confidence scoring on the brief itself. |

## Architecture

```
samples/stix_bundles/                STIX 2.1 JSON bundles
    01-phishing-campaign.json
    02-cve-advisory.json
    │
    ▼
┌──────────────────────────────────────┐
│ feed.loader.load_bundle()            │  parse JSON, index by object ID
│   → StixBundle                       │
└──────────────┬───────────────────────┘
               │
               ▼
┌──────────────────────────────────────┐    ┌──────────────────────────────┐
│ brief.BriefGenerator                 │    │ notables.emit_notables()     │
│   if API key:  call Claude           │    │   one CIM event per          │
│   else:         StubClient (offline) │    │   indicator                  │
│   → markdown brief                   │    │   linked_to via STIX rels    │
└──────────────┬───────────────────────┘    └──────────────┬───────────────┘
               │                                            │
               ▼                                            ▼
┌──────────────────────────────────────┐    ┌──────────────────────────────┐
│ brief.verify_citations()             │    │ out/notables/<bundle>.json   │
│   extract every [type--uuid] ref     │    │   Splunk HEC ingestible      │
│   confirm each resolves              │    └──────────────────────────────┘
│   → list[CitationFinding]            │
└──────────────┬───────────────────────┘
               │
               ▼
┌──────────────────────────────────────┐
│ out/briefs/<bundle>.md               │
│ out/citation_audit.json              │
└──────────────────────────────────────┘
```

## The citation verifier — the differentiator

Most "LLM summarizer" projects produce plausible-sounding text with no
mechanism for confirming the text is actually grounded in source data.
That's fine for low-stakes summarization — a meeting summary, a slide
recap. It's not fine for a SOC brief that drives blocking decisions.

This project's verifier walks the generated markdown, extracts every
`[type--uuid]` reference, and confirms each ID exists in the source
STIX bundle. The verification result is structured:

```python
[
  CitationFinding(
    citation="campaign--apt-finsector-2026q1",
    resolved=True,
    occurrences=3,
    object_type="campaign",
  ),
  CitationFinding(
    citation="threat-actor--made-up-actor-not-in-bundle",
    resolved=False,    # ← hallucination
    occurrences=1,
    object_type="threat-actor",
  ),
]
```

Any `resolved=False` finding is a hallucination. The `summarizer.py`
CLI exits non-zero on any hallucination, so the verifier doubles as a
CI / pre-distribution gate. A SOC can subscribe to the summarizer's
output without manually re-checking every claim, because the verifier
already did.

## The stub client — offline / CI-friendly mode

A real Claude call is non-deterministic, takes ~5–15 seconds per
bundle, and requires an API key. None of those properties are
compatible with a CI regression check or local development without a
key.

The `StubClient` is a deterministic offline replacement that constructs
a brief by walking the bundle's actual STIX objects and assembling
canonical sections (executive summary, IOC list, TTPs, recommended
actions). Every citation it produces is, *by construction*, a real
bundle object ID — so the stub never hallucinates.

The CI run uses the stub client, asserts zero hallucinations, and
fails the build if the stub or the verifier ever drift apart. Local
runs without an API key get the same behavior. With an API key set,
the real Claude call is used and the verifier exercises the negative
path against any hallucinated citations.

The negative-path coverage (verifier rejecting fake IDs) is exercised
by the test suite, which feeds hand-crafted "bad" briefs containing
intentionally fake STIX IDs and asserts the verifier flags them.

## Quick start

```bash
cd 07-threat-intel-summarizer
pip install -r requirements.txt

# Offline run — uses stub client, no API key needed
python3 summarizer.py --offline

# Output structure
ls out/
#   briefs/    notables/    citation_audit.json

# Inspect a generated brief
head -40 out/briefs/01-phishing-campaign.md

# Inspect the citation audit
cat out/citation_audit.json

# Real Claude run — set API key first
ANTHROPIC_API_KEY=sk-ant-... python3 summarizer.py

# Tests (offline)
pytest -q
```

## Output

`out/briefs/<bundle>.md` — analyst-readable markdown brief per
bundle. Sections: title, executive summary, IOCs, TTPs, recommended
actions. Every factual claim cites a STIX object ID.

`out/notables/<bundle>.json` — CIM-shaped Splunk notable events, one
per indicator in the bundle. Each event includes the indicator value
(domain, IP, hash, etc.), the indicator type (auto-classified from
the STIX pattern), and a `linked_to` array of related STIX object IDs
derived from the bundle's relationship objects. Drop on a HEC endpoint
and downstream Splunk ES correlation searches (Project 4) fire on
matched IOCs.

`out/citation_audit.json` — per-bundle citation verification summary.
For each bundle: number of unique citations, number resolved, number
hallucinated, and the list of any hallucinated citation IDs.

## Splunk integration

Each notable event ships with `cim_eventtype="ai_threat_intel_indicator"`
and `signature="threat_intel_summarizer"`. A typical Splunk ES
correlation search consuming these events:

```spl
index=aisec sourcetype="aisec:threat_intel" cim_eventtype="ai_threat_intel_indicator"
| stats values(indicator_values) as iocs values(linked_to) as linked
        by indicator_id, indicator_type
| `notable_event(threat_intel_indicator, "medium", "New IOC from threat-intel feed")`
```

Combine with Project 4's correlation generator and the rule library
already includes templates for cross-referencing these IOCs against
runtime detections from Projects 1, 3, and 5.

## What's not in MVP (roadmap)

- **Live TAXII 2.x client.** `taxii2-client` package, polling against
  configured TAXII servers, scheduled-update behavior. The MVP reads
  bundles from disk, which is the right shape for testing and CI but
  not for production.
- **Confidence scoring on the brief.** Each cited claim should carry a
  confidence value derived from the STIX object's own `confidence`
  field (when present) and the relationship density supporting it.
- **Multi-bundle clustering.** When the same threat actor or
  vulnerability appears across multiple bundles, the summarizer should
  produce a single consolidated brief rather than one per bundle.
- **Adaptive prompt depth.** The "adaptive" in the project name —
  per-analyst preferences for brief depth (one-paragraph TLDR vs. full
  campaign treatment), per-feed routing rules, scheduled digests.
- **Output content safety.** Wire Project 5's output compliance
  monitor into the brief-emit path. The brief is LLM-generated content
  and should pass through the same PII / classification / policy
  filters that runtime LLM responses do.

## Why this matters for the portfolio

Project 7 is the first project in the portfolio where Claude *produces
user-visible content* rather than judging or scoring text. That shift
introduces a new failure mode — hallucination — that the rest of the
portfolio doesn't have to deal with. The citation verifier is the
control that closes that gap.

The pattern matters beyond this specific project. Any LLM application
that produces analyst-facing artifacts (incident reports, executive
briefings, vulnerability triage notes, threat-hunting playbooks) needs
the same kind of provenance binding to be trusted in regulated
environments. Citation verification — every claim bound to a source
ID, hallucinated references rejected — is the architectural pattern
that turns LLM-generated content from a productivity boost into a
deployable security control. This project demonstrates the pattern in
the cleanest possible setting.

It also closes a loop with Project 4's correlation generator: every
indicator in every bundle becomes a Splunk notable, and Project 4's
existing rule templates already correlate those notables with the
runtime detections from Projects 1, 3, and 5. The portfolio's
seven projects now operate as one coherent pipeline.
