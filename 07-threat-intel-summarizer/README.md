# 07 — Adaptive Threat Intelligence Summarizer

Consumes **STIX 2.1 / TAXII 2.x** feeds, deduplicates and clusters
indicators, then produces **analyst-ready summaries** pushed into Splunk
ES as notables and a daily digest. Adaptive because summary depth and
recipient scope are tuned per-feed and per-analyst preference.

**Status:** Spec / scaffold — populated next.

## Threat model — sort of

This project is more "analyst force multiplier" than detection, but the
threat-modeling discipline still applies:

| | |
|---|---|
| **Attacker capability** | Feeds may be poisoned by upstream sources (TAXII server compromise, false-flag indicators). |
| **Target asset** | Analyst attention budget, blocklist correctness. |
| **In scope** | Source-reputation weighting; LLM-summary hallucination guardrails (every claim must carry a STIX object reference). |

## Architecture

```
ingest/
  taxii_client.py      ── TAXII 2.1 poll loop, watermark per feed
  stix_loader.py       ── STIX 2.1 → normalized internal model
analytics/
  cluster.py           ── group by infrastructure, actor, campaign
  reputation.py        ── per-source weight; downweight on stale / unverified
summarize/
  brief.py             ── Claude-authored daily brief, with citation footnotes
  notables.py          ── high-severity indicators → Splunk ES notables
output/
  splunk_hec.py
  email.py             ── analyst digest
```

## Deliverables

1. Daily digest in markdown: actor, campaign, top-5 IoCs with confidence
   and source list. Every sentence cites a STIX `id`.
2. Splunk ES notables for indicators above a configured confidence × severity
   threshold, dedup'd by `pattern_hash`.
3. A `lookup_threat_intel.csv` refreshed hourly for use in correlation
   searches across the rest of the portfolio.

## Hallucination guardrail

Summaries are generated with a constrained Claude system prompt: every
sentence must end with a `[stix:object-id]` citation, validated by a
post-processor against the source bundle. Sentences without valid
citations are dropped.

## Splunk / SOC tie-in

Direct: notables, lookups, dashboards. The project doubles as a worked
example of "use Claude inside a SOC workflow without trusting it."

## Compliance angle

Aligns with **NIST 800-53 PM-16 Threat Awareness Program** and
**SI-5 Security Alerts, Advisories, and Directives**.
