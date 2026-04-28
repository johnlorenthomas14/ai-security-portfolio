# 08 — NIST AI RMF Compliance Gap Analyzer

Continuous-compliance tooling for **NIST AI RMF 1.0** (Govern / Map /
Measure / Manage), modeled on the same Splunk-backed control-evidence
pattern the user has shipped at federal customers via Qmulos
(Q-Compliance). This is the capstone project — it consumes outputs from
projects 1–7 as evidence sources.

**Status:** Spec / scaffold — populated next.

## What this is, in one paragraph

A scriptable compliance engine that reads AI RMF subcategory definitions,
maps each one to the evidence sources that satisfy it, queries those
sources, and produces a **gap report** plus an **ATO-ready evidence
package**. Designed to be runnable on a schedule so a control's status is
"as of now," not "as of the last audit."

## Architecture

```
controls/
  ai_rmf_1_0.yml            ── full subcategory list, machine-readable
  mappings/
    rmf_to_800_53.yml       ── crosswalk to NIST 800-53 (federal anchor)
    rmf_to_evidence.yml     ── subcategory → evidence query

evidence/
  splunk_query.py           ── runs SPL against an ES instance, returns rows
  github_query.py           ── PR/CODEOWNERS coverage for AI repos
  jira_query.py             ── AI risk register tickets
  policy_doc.py             ── parse PDFs/docx for governance policies

engine/
  evaluate.py               ── per-subcategory: pass / partial / gap / unknown
  report.py                 ── markdown + docx evidence package
  diff.py                   ── change since last run

bin/
  analyze.py                ── CLI: produce gap report
  watch.py                  ── scheduled daemon: re-evaluate, alert on regressions
```

## Evidence sourcing

Each AI RMF subcategory is satisfied by one or more queries:

| Subcategory | Evidence query (example) |
|---|---|
| GOVERN 1.1 (policies/procedures) | Latest version of `ai-policy.md` in the governance repo, signed off by `@ciso`. |
| MAP 2.3 (system context documented) | Per-app model card present in `models/` repo. |
| MEASURE 2.7 (security and resilience) | Project 1 detection volume in last 7d ≥ N; Project 4 dashboards healthy. |
| MEASURE 2.10 (privacy risk managed) | Project 5 redaction rate within tolerance per app. |
| MANAGE 2.3 (response and recovery) | IR runbook exists, last tabletop within 12 months. |

## Deliverables

1. `gap_report.md` per run: per-subcategory status (pass / partial /
   gap / unknown) with evidence links and a "what's missing" line.
2. `evidence_package/` zip with the artifacts referenced, suitable for
   submission as ATO evidence.
3. Splunk dashboard panels: control coverage heatmap; subcategories that
   regressed in the last 30 days; top gaps by program.

## Why this caps the portfolio

It demonstrates the user's federal compliance posture (Qmulos, NIST 800-53)
extended cleanly into the AI domain — exactly the rare combination an AI
Security Engineer hiring manager at a regulated org is hunting for.
The other seven projects are wired in as evidence sources, so the
portfolio reads as a **single coherent system**, not eight disconnected
demos.
