# 05 — LLM Output Safety & Compliance Monitor

A **FedRAMP-aware serverless output auditing layer** that sits between an
LLM and its callers. It inspects every completion for PII, secrets,
classification markings, and policy violations, redacts or blocks where
required, and emits a tamper-evident audit log.

**Status:** Spec / scaffold — populated next.

## Threat model

| | |
|---|---|
| **Attacker capability** | Either (a) an end user attempting to elicit prohibited content, or (b) an upstream injection that has already coerced the model. |
| **Target asset** | Downstream consumer (user, app, tool) of the model output. |
| **In scope** | PII (incl. CUI markers), secrets/credentials, classification banners, policy-violation patterns, hallucinated URL exfiltration. |
| **Out of scope** | Multi-turn jailbreak detection (Project 1's job at the input layer). |

## Architecture

```
              ┌────────────┐
caller ─────► │ LLM        │ ──► raw completion
              └─────┬──────┘
                    ▼
              ┌────────────────────────────┐
              │ Output Compliance Monitor  │
              │  ┌──────────┐ ┌──────────┐ │
              │  │ PII/CUI  │ │ Secrets  │ │
              │  ├──────────┤ ├──────────┤ │
              │  │ Policy   │ │ Claude   │ │
              │  │ rules    │ │ judge    │ │
              │  └──────────┘ └──────────┘ │
              │     redact / block / pass  │
              └────────────┬───────────────┘
                           ▼
              audit log → S3 (Object Lock) + Splunk HEC
                           ▼
                       caller
```

## FedRAMP-aware bits

- Deployable to **AWS GovCloud** (Lambda + API Gateway, KMS CMK with
  customer-managed keys, S3 with Object Lock for WORM audit storage).
- Audit log entries are **hash-chained** (each entry includes prev hash)
  so tampering is detectable without an external timestamping service.
- All optional egress (Splunk HEC, model API) is configurable to stay
  inside an authorization boundary.

## Deliverables

```
infra/                  ── Terraform: Lambda + APIGW + S3 + KMS, GovCloud-ready
monitor/
  pii.py                ── Presidio + federal recognizers
  secrets.py
  policy.py             ── YAML-driven org policy (no profanity, no PHI in product X, ...)
  judge.py              ── Claude with output-only system prompt
  audit.py              ── hash-chained, JSON-line audit writer
api/
  handler.py            ── single Lambda entrypoint
tests/
```

## Compliance mapping

Maps cleanly to FedRAMP Moderate baseline controls:
**AC-4 Information Flow Enforcement**, **AU-2/3/9 Audit Events / Content / Protection**,
**SC-8 Transmission Confidentiality**, **SI-12 Information Output Filtering**,
**SI-15 Information Output Filtering for Privileged Functions**.

AI RMF: **MEASURE 2.10**, **MANAGE 4.1**.

## Splunk / SOC tie-in

Every audit record is dual-written to S3 (Object Lock) and Splunk HEC.
Splunk ES correlation searches in Project 4 watch for redaction/block
rate spikes per principal, which usually indicates either a campaign or
a model regression.
