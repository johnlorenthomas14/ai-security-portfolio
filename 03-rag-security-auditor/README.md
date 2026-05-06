# 03 — RAG Pipeline Security Auditor

[![CI](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml/badge.svg)](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP%20LLM-LLM01%20%7C%20LLM02%20%7C%20LLM07-orange.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![NIST AI RMF](https://img.shields.io/badge/NIST%20AI%20RMF-1.0-blue.svg)](https://www.nist.gov/itl/ai-risk-management-framework)

> **Static corpus scanner that finds indirect-injection payloads, PII,
> credentials, and sensitivity-marker leaks in retrieval-augmented-generation
> corpora *before* they reach a production LLM.** Reuses Project 1's
> prompt-injection detector as the indirect-injection scanner; produces
> Splunk-ingestible JSON findings plus a Markdown audit report keyed by
> NIST AI RMF subcategory.

**Status:** Working MVP. Ships with four scanner classes, six demo
documents (several intentionally polluted), pytest end-to-end coverage,
and a CI job that runs the full audit on every push.

## Demo

[![asciicast](https://asciinema.org/a/ey747xtH1ZX1djfX.svg)](https://asciinema.org/a/ey747xtH1ZX1djfX)

90-second walkthrough — the corpus directory, the auditor running over
six demo documents (several intentionally polluted), the severity
rollup with one critical PEM-block finding plus high-severity
credential and CUI findings, the Splunk-ingestible JSON, and the
pytest suite. Click the cast above to play, or run it yourself:

```bash
cd 03-rag-security-auditor
./demo.sh
```

> **Engineering write-up:** [`WRITEUP.md`](./WRITEUP.md) — the why
> behind every design decision. Why static corpus scanning vs. live
> RAG probing, why these four scanner classes, the false-positive
> trade-offs (regex vs. NER for PII, redaction-in-report for secrets),
> Splunk integration with batch / ack / Cribl detail, and how the
> three-project chain produces continuous-monitoring evidence across
> all four NIST AI RMF functions. ~3,300 words, 12-minute read.

## Threat model

| | |
|---|---|
| **Attacker capability** | Author or modify documents that end up in a RAG corpus the LLM application retrieves from — internal wikis, support knowledge bases, shared drives, public web crawls, third-party document feeds. |
| **Target asset** | The host LLM application's instruction integrity (indirect injection), its data-minimization posture (PII / secret leaks via retrieved context), and the corpus's classification posture (sensitivity-marker spillage into accessible content). |
| **In scope** | Indirect prompt injection (LLM01) · PII disclosure (LLM02) · Sensitive-Information Disclosure incl. secrets (LLM02) · System-prompt leakage via planted docs (LLM07) · Sensitivity-handling marker leaks (CUI / FOUO / classified / ITAR / PHI) |
| **Out of scope (MVP)** | Embedding inversion · Membership-inference attacks · Live RAG-system probing (different shape — separate project) · Authn/authz audit of the retrieval layer (depends on RAG framework specifics) · Binary document parsing (PDF/DOCX — roadmap) |

## Architecture

```
                ┌──────────────────────────┐
   corpus/  ───►│ load_corpus              │  reads .md/.txt/.json/.yaml/etc.
   *.md         │  → list[Document]        │
   *.txt        └────────────┬─────────────┘
   ...                       │
                             ▼
            ┌────────────────────────────────────┐
            │  scan_corpus — runs every scanner  │
            │  over every document               │
            └────────────────┬───────────────────┘
                             │
            ┌────────────────┼────────────────────┐
            ▼                ▼                    ▼
   ┌─────────────────┐ ┌──────────────┐  ┌────────────────────┐
   │IndirectInjection│ │ PIIScanner   │  │ SecretsScanner     │
   │  (Project 1)    │ │  email/SSN/  │  │  AWS/GH/Anthropic/ │
   │                 │ │  phone/CC    │  │  PEM/.env vars     │
   └─────────────────┘ └──────────────┘  └────────────────────┘
                                          ┌────────────────────┐
                                          │ SensitivityScanner │
                                          │  CUI/FOUO/CLASSIFIED│
                                          │  ITAR/PHI/PROPRIETARY│
                                          └────────────────────┘
                             │
                             ▼
                ┌────────────────────────┐
                │ findings.json (CIM)    │   Splunk HEC ingestible
                │ audit_report.md        │   AI RMF-aligned narrative
                └────────────────────────┘
```

Four scanners, one shared `DocumentScanner` protocol. Each returns
`Finding` objects tagged with OWASP LLM Top 10 category, MITRE ATLAS
technique, and NIST AI RMF subcategory. The auditor aggregates and the
report writer emits both formats. Adding a new scanner is one file in
`scanners/`; adding new corpus formats is extending the extension list
in `auditor.py`.

## The four scanners

**`IndirectInjectionScanner`** — paragraph-level scan that pipes each
non-empty paragraph through Project 1's `PromptInjectionDetector` (in
heuristic-only mode, no API key required). Any paragraph the detector
classifies as `suspicious` or `malicious` becomes a finding tagged with
LLM01 / `AML.T0051`. This is the closing-the-loop piece — a payload
detected at corpus-ingestion time is one the input layer never has to
deal with at runtime.

**`PIIScanner`** — deterministic regex-based detection for emails, US
SSNs, US phone numbers, and Luhn-validated credit-card numbers. Maps to
LLM02 / `AML.T0024` / `MEASURE 2.10`. Deliberate scope cut: NER-shaped
PII (names, addresses) is roadmap, not MVP — regex on structured PII is
high-precision and the right shape for a corpus-ingestion gate.

**`SecretsScanner`** — credential and API-key detection covering AWS
keys (AKIA/ASIA/AROA/AIDA), GitHub tokens (modern prefixed formats),
Slack tokens, Anthropic keys, OpenAI keys, PEM-block private keys, and
.env-style variable assignments naming common credential variables.
Excerpts in the report redact the actual leaked value so the audit
itself does not become a secondary leak vector.

**`SensitivityScanner`** — classification / handling-marker detection
for CUI, FOUO, CONFIDENTIAL, SECRET, TOP SECRET, ITAR / Export-controlled,
PROPRIETARY / TRADE SECRET, ATTORNEY-CLIENT PRIVILEGED, and PHI / HIPAA.
A single document can carry multiple markers; the scanner emits one
finding per marker-kind per document to avoid noise. Maps to LLM02 /
`GOVERN 1.3`.

## Quick start

```bash
cd 03-rag-security-auditor
pip install -r requirements.txt
pip install -r ../01-prompt-injection-pipeline/requirements.txt   # for the detector

# Audit the shipped demo corpus (6 documents, intentionally polluted).
python auditor.py --corpus corpus/demo

# Audit a real corpus.
python auditor.py --corpus /path/to/your/corpus --output ./audit-out

# Tests (offline).
pytest -q
```

## Output — findings.json + audit_report.md

`findings.json` — machine-readable, one entry per finding. CIM-friendly
(`cim_eventtype="ai_rag_finding"`, `signature`, `event_severity`,
`event_time`) so a scheduled audit becomes a recurring scan in Splunk
Enterprise Security or Cortex XSIAM.

`audit_report.md` — analyst-readable Markdown:

- Severity rollup (critical / high / medium / low) with single-line totals.
- Executive summary that calls out the action a SOC or GRC team needs to take.
- Findings grouped by category, by document, by OWASP, and by AI RMF subcategory.
- Per-finding details — the matched line, line number, document path, scanner that fired, rationale.

## Splunk integration

```spl
index=aisec sourcetype="aisec:rag_audit" cim_eventtype="ai_rag_finding" severity IN ("critical","high")
| stats count values(category) as categories values(scanner) as scanners
        by document_path
| `notable_event(rag_corpus_finding, "high", "RAG corpus contains restricted content")`
```

The same HEC-ingestion notes that apply to Projects 1 and 2 apply here:
HEC is the idiomatic ingestion path for scheduled-emit-events;
batch-endpoint POSTs and Cribl-fronting are the production-tuning levers
for license-constrained federal deployments.

## What's not in MVP (roadmap)

- **Binary document parsing.** PDFs, DOCX, and PPTX make up most real
  corpora. The current MVP scans text-only formats. Adding `pypdf` or
  `python-docx` is a one-file extension to `auditor.py`'s extension list.
- **NER-shaped PII.** Names and addresses need a proper NER model
  (spaCy, Microsoft Presidio). The regex MVP catches structured PII
  with high precision; NER fills the qualitative gaps with managed
  false-positive cost.
- **Embedding-similarity scan.** A scanner that flags documents whose
  embeddings fall close to known-attack-corpus vectors — useful for
  catching novel injection phrasings the regex layer misses.
- **Per-document risk score.** Aggregate the findings for one document
  into a single risk score and an ingest / quarantine / block recommendation.
- **Live RAG-system audit.** Probe a running RAG endpoint (the way
  Project 2 probes a running LLM) — separate project, different shape.

## Why this matters for the portfolio

Project 1 detects injection at the LLM input layer at runtime. Project 2
probes deployed LLM applications for vulnerability classes. Project 3
shifts left — auditing the corpus before any of those runtime issues
have a chance to manifest. The three projects together form the full
defense-in-depth chain: pre-ingestion scanning (P3), runtime input
inspection (P1), and continuous adversarial validation (P2).

The NIST AI RMF mapping makes the same artifact useful for federal
governance. Corpus audits are exactly the kind of evidence a Manage-function
control needs — *"every document that enters the RAG corpus is scanned
against four control classes; results are filed as continuous-monitoring
evidence under MEASURE 2.7, MEASURE 2.10, and GOVERN 1.3."* That is
the AI-governance posture federal customers need and very few off-the-shelf
RAG products provide today.
