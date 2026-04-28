# 06 — AI Model Supply Chain Risk Scanner

Scans third-party / open-source models (Hugging Face, local artifacts)
for **poisoning indicators, malicious deserialization payloads, and
provenance gaps**. Produces a model-card-style risk report and an SBOM
fragment suitable for ingestion alongside CycloneDX/SPDX.

**Status:** Spec / scaffold — populated next.

## Threat model

| | |
|---|---|
| **Attacker capability** | Publishes or tampers with a model artifact (weights, tokenizer, config) that a downstream consumer pulls and runs. |
| **Target asset** | The host that loads the model and any data/tool the model can reach at inference time. |
| **In scope** | Pickle/torch deserialization payloads; tokenizer trojans; trigger-pattern probing; metadata vs. signature mismatch; license/provenance gaps. |
| **Out of scope** | Steganographic backdoors invisible to behavioral probing. |

## Architecture

```
fetcher/             ── HF Hub, local filesystem, S3
scanners/
  pickle_scan.py     ── safe-load AST walk; flags GLOBAL/REDUCE on os/subprocess/shutil/builtins
  tokenizer_scan.py  ── special-token sniffer; trigger-token regression vs. base
  trigger_probe.py   ── prompt the model with curated trigger phrases (SOTA backdoors)
  metadata.py        ── pulls model card; verifies sha256 against HF API
  sbom.py            ── emits CycloneDX-flavored fragment
report/
  risk_report.md     ── analyst-readable
  sbom.cdx.json
  findings.jsonl
```

## Deliverables

1. CLI: `scan.py --model meta-llama/<x> --report out/`
2. Per-finding severity + CVE-style ID (`AISC-YYYY-NNNN` for repeatability).
3. SBOM fragment that can be merged into a parent app SBOM for FedRAMP
   inventory requirements (CM-8).

## Federal / compliance angle

NIST 800-53: **CM-8 System Component Inventory**, **CM-10 Software Usage
Restrictions**, **SR-3 Supply Chain Controls and Processes**, **SR-11
Component Authenticity**. NIST AI RMF: **MAP 2.1**, **MEASURE 2.6**.

## Splunk / SOC tie-in

Findings emit on `aisec.supply_chain` so a Splunk dashboard can show a
"models in production by risk score" panel keyed off the same SBOM
fragment used by the agency's CMDB.
