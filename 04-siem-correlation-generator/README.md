# 04 — SIEM Correlation Rule Generator for AI Workloads

Generates **Splunk ES correlation searches** (and Sigma rules as a
secondary output) for AI-specific threats. Each rule is mapped to a
**MITRE ATLAS** technique and emits a properly tagged notable event.

**Status:** Spec / scaffold — populated next.

## Why this is the project the user is uniquely positioned to ship

Most "AI security" content stops at the application layer. This project
reframes AI threats as Splunk detection content — content packs, savedsearches.conf,
data models, drilldowns — which is exactly the muscle the user spent nine
years building.

## Coverage

| ATLAS technique | Detection idea |
|---|---|
| AML.T0051 Prompt Injection | Notables produced by Project 1 piped into ES |
| AML.T0054 LLM Jailbreak | Persona/role-override attempts per session |
| AML.T0040 ML Model Inference API Access | Anomalous query volume / token spend per principal |
| AML.T0024 Exfiltration via ML Inference API | Model output volume + entropy spikes |
| AML.T0048 External Harms (PII) | Output Compliance Monitor (Project 5) violations |
| AML.T0034 Cost Harvesting | $/principal/hour breach of baseline |
| AML.T0010 ML Supply Chain Compromise | Project 6 findings on a registered model |

## Deliverables

```
rules/
  ai_prompt_injection_notable.conf
  ai_jailbreak_persona_takeover.conf
  ai_inference_api_abuse_volume.conf
  ai_model_output_pii_leak.conf
  ai_token_spend_baseline_breach.conf
  ai_supply_chain_compromise.conf
data_models/
  ai_security.json     ── CIM-style data model
generator.py            ── Claude-assisted: ATLAS technique → SPL skeleton
tests/
  test_spl_lints.py    ── runs `splunk btool` lint via container (optional)
```

## Architecture

```
input:  attack scenario  +  log schema (sourcetype + sample events)
        │
        ▼
   ┌────────────────────────┐
   │ generator.py           │  Claude (sonnet) with a constrained
   │ ATLAS-aware SPL author │  template; output schema-validated
   └────────────────────────┘
        │
        ▼
   savedsearches.conf stanza  +  notable_event mapping  +  drilldown query
```

## Splunk / SOC tie-in

This project IS the Splunk tie-in. Each generated rule is an ES correlation
search, ready to drop into a content pack. The data model gives analysts a
consistent set of fields to pivot across all eight projects.

## Compliance mapping

NIST 800-53 **AU-6 Audit Review/Analysis/Reporting** and **SI-4 System
Monitoring**. AI RMF **MEASURE 2.7** (security and resilience).
