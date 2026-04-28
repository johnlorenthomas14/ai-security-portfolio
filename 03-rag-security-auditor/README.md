# 03 — RAG Pipeline Security Auditor

Audits a retrieval-augmented-generation pipeline for two failure modes
that production RAG systems get wrong almost universally:

1. **Sensitive-data leakage** — the corpus indexed for retrieval contains
   PII, secrets, or above-classification material that ends up in
   completions.
2. **Indirect prompt injection** — adversarial content embedded in
   retrievable documents that hijacks the model when retrieved.

**Status:** Spec / scaffold — populated next.

## Threat model

| | |
|---|---|
| **Attacker capability** | Can write into one or more sources the RAG pipeline indexes (wiki page, ticketing system, public web crawl, S3 bucket). |
| **Target asset** | The downstream LLM application using the RAG output and any tools it can invoke. |
| **In scope** | Static-corpus PII/secret scanning; injection-in-document detection (reuses Project 1's detector); chunk-boundary leakage; over-permissive retrieval ACLs. |
| **Out of scope** | Vector-store database vulnerabilities; retrieval-time DoS. |

## Architecture

```
sources/               ── pluggable readers (S3, Confluence, GDrive, local FS)
auditor/
  pii_scanner.py       ── Presidio + custom federal-flavored recognizers
  secret_scanner.py    ── trufflehog-style entropy + regex
  injection_scanner.py ── reuses ../01-prompt-injection-pipeline/detector
  acl_diff.py          ── compares document ACL vs. retrieval API caller identity
report/
  findings.jsonl
  splunk_lookup.csv    ── doc_id → risk_score lookup for drilldown
```

## Deliverables

1. CLI: `python auditor.py --source s3://corpus --report out/`.
2. Per-document risk score (PII × secret × injection × ACL drift).
3. A `splunk_lookup.csv` ready to drop into a Splunk lookup definition so
   analysts can pivot from "model said X" to "what document caused it."

## Splunk / SOC tie-in

Findings emit on `aisec.rag_auditor` with CIM-style fields. Pair with
Project 4's correlation-rule generator to fire a notable when a model
output cites a high-risk document.

## Federal / compliance angle

PII recognizers include CUI markers (`CUI//SP-PRVCY`), ITAR keywords, and
classification banners common in federal corpora. Maps to NIST 800-53
**SI-12 Information Output Filtering** and **SC-8 Transmission
Confidentiality**, plus AI RMF **MEASURE 2.10**.
