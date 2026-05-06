# 08 — NIST AI RMF Compliance Gap Analyzer

[![CI](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml/badge.svg)](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![NIST AI RMF](https://img.shields.io/badge/NIST%20AI%20RMF-1.0-blue.svg)](https://www.nist.gov/itl/ai-risk-management-framework)
[![Capstone](https://img.shields.io/badge/portfolio-capstone-purple.svg)](../README.md)

> **The capstone. Reads outputs from Projects 1–7, maps every finding
> to its NIST AI RMF 1.0 subcategory, computes per-subcategory and
> per-function coverage, and produces a continuous-monitoring evidence
> document plus a priority-ordered gap report.** The same
> control-evidence pattern Qmulos Q-Compliance / Q-Audit applies to
> NIST 800-53 — extended directly into AI governance.

**Status:** Working MVP. Ships with a representative AI RMF subcategory
catalog (~36 subcategories spanning all four functions), an evidence
ingestor that walks every upstream project's output, coverage analysis
with function-level rollups, JSON + Markdown gap reports, a 14-test
pytest suite, and a CI job that runs the analyzer over the whole
portfolio on every push.

## Demo

[![asciicast](https://asciinema.org/a/Jb7bACNliktiREzo.svg)](https://asciinema.org/a/Jb7bACNliktiREzo)

90-second walkthrough — the AI RMF subcategory catalog (35 entries across
all four functions), the analyzer reading evidence from every upstream
project's output, the per-function rollup (`GOVERN 22%`, `MAP 17%`,
`MEASURE 40%`, `MANAGE 40%`), the gap report's executive summary, the
covered-subcategories list with contributing-project references, and
the pytest suite. Click the cast above to play, or run it yourself:

```bash
cd 08-nist-ai-rmf-gap-analyzer
./demo.sh
```

## What this project does

Projects 1–7 each tag every finding with a `cim_eventtype`, an OWASP
LLM Top 10 category, MITRE ATLAS technique IDs, and a NIST AI RMF
subcategory. Project 8 reads those tags from each project's output,
indexes evidence by AI RMF subcategory, and produces:

- A **per-subcategory coverage map** — for every catalogued subcategory,
  the list of evidence items contributing to it (with source-file paths
  and contributing project names).
- A **per-function rollup** — Govern / Map / Measure / Manage coverage
  percentages.
- A **gap report** — subcategories with zero evidence, ordered by
  portfolio-relative priority. The high-priority gaps are the ones a
  federal AI program would expect a Manage-function control to address.

The output doubles as continuous-monitoring evidence: a federal
program operating under an authority-to-operate can file the
generated `gap_report.md` and `coverage.json` as Measure-function
evidence, with the upstream project outputs as the supporting artifacts.

## Architecture

```
   AI Security Portfolio
   │
   ├── 01 prompt-injection-pipeline ── eval_set + CI floor    ┐
   ├── 02 ai-red-team-framework      ── out/findings.json     │
   ├── 03 rag-security-auditor       ── out/findings.json     │  ingest/sources.py
   ├── 04 siem-correlation-generator ── templates/*.yaml      ├──► reads each
   ├── 05 output-compliance-monitor  ── out/audit.jsonl       │   project's output
   ├── 06 model-supply-chain-scanner ── out/findings.json     │   files, extracts
   └── 07 threat-intel-summarizer    ── out/citation_audit    ┘   airmf_subcategory
                                                                  tags
                              │
                              ▼
              ┌──────────────────────────────────┐
              │  rmf/coverage.compute_coverage() │  match each evidence item
              │   evidence × catalog →           │  to its AI RMF subcategory
              │   CoverageReport                 │
              └──────────────┬───────────────────┘
                             │
                             ▼
                ┌────────────────────────┐
                │ out/coverage.json      │   machine-readable
                │ out/gap_report.md      │   GRC-reviewer-readable
                └────────────────────────┘
```

## The catalog

`rmf/catalog.py` ships a representative subset of ~36 NIST AI RMF 1.0
subcategories spanning all four functions. Each entry has:

- The canonical NIST ID (e.g. `MEASURE 2.7`)
- Function (Govern / Map / Measure / Manage)
- Short name (~10 words)
- Description (paraphrased from NIST AI 100-1)
- Portfolio-relative priority (high / medium / low / informational)

The subset includes:
- All subcategories the portfolio's projects actually provide evidence for
- A representative span of *uncovered* subcategories, so the gap report
  has real "gap" output to demonstrate

For a production deployment, replace the catalog with a full extract
from NIST AI 100-1. The ingest and coverage logic is catalog-agnostic.

## The ingestor — per-project extractors

Each project's output has its own shape, so `ingest/sources.py` ships
five extractors:

| Project | Source file | Extractor |
|---|---|---|
| 01 | `eval_set.jsonl` + CI workflow | `_from_project_1` (synthesized — eval + CI floor as MEASURE 1.1 / 2.7 / GOVERN 1.5 evidence) |
| 02 | `out/findings.json` | `_from_json_findings` |
| 03 | `out/findings.json` | `_from_json_findings` |
| 04 | `templates/*.yaml` | `_from_project_4` (parses each template's `airmf:` field) |
| 05 | `out/audit.jsonl` | `_from_audit_jsonl` (reads finding airmf tags + treats audit log itself as GOVERN 1.5 / MANAGE 4.3 evidence) |
| 06 | `out/findings.json` | `_from_json_findings` |
| 07 | `out/citation_audit.json` + `out/notables/*.json` | `_from_project_7` |

Each extractor is wrapped in a try/except — an unreadable or missing
output file from one project never blocks the analyzer from processing
the others.

## Quick start

```bash
cd 08-nist-ai-rmf-gap-analyzer
pip install -r requirements.txt

# Run the analyzer over the portfolio (assumes default portfolio root)
python3 analyzer.py

# Output structure
ls out/
#   coverage.json    gap_report.md

# Inspect the gap report
head -50 out/gap_report.md

# Inspect the JSON for programmatic consumption
python3 -m json.tool out/coverage.json | head -40

# Tests (offline)
pytest -q
```

## Output

`out/coverage.json` — machine-readable. Includes the run metadata, the
function rollup, every subcategory with its covered/uncovered status,
and a separate `gaps` array for filtered consumption.

`out/gap_report.md` — GRC-reviewer-readable Markdown. Sections:

- **Coverage by AI RMF function** — Govern / Map / Measure / Manage table.
- **Executive summary** — high-priority gap count, action-oriented.
- **Covered subcategories — evidence references** — for each covered
  subcategory: function, priority, contributing projects, evidence items
  with source-file paths.
- **Gaps — subcategories with no evidence** — priority-ordered table.

## What "covered" actually means

A subcategory is covered when at least one upstream project has emitted
a finding tagged with that subcategory. That's a deliberately
permissive bar — the analyzer reports presence-of-evidence, not
sufficiency-of-evidence. Sufficiency is a human judgment that depends
on the program's risk tolerance and the AI system's deployment context.

The analyzer's job is to make presence-of-evidence machine-checkable.
Sufficiency lives in the auditor's review of the source artifacts the
gap report references.

## Why this matters for the portfolio

Project 8 ties the seven previous projects into one coherent governance
artifact. Without it, the portfolio is seven independent technical
demos. With it, the portfolio is *a continuous-compliance pipeline for
AI workloads* — every detection event flowing through the projects
becomes evidence for a NIST AI RMF subcategory, and the resulting
coverage map is the artifact a federal program files under continuous
monitoring.

The pattern is the same one Qmulos Q-Compliance and Q-Audit apply to
NIST 800-53. Drop a similar layer over the AI security pipeline, and
the federal-compliance angle stops being marketing language and starts
being a measurable property of the portfolio. That is the thesis the
portfolio's eight projects are built to demonstrate.

## What's not in MVP (roadmap)

- **Full NIST AI 100-1 catalog.** The MVP ships ~36 subcategories — a
  representative subset. A production deployment would extract the
  full ~73-subcategory catalog with NIST's official descriptions.
- **Trend tracking over time.** Run the analyzer on a schedule, store
  each run's `coverage.json`, and produce a coverage-over-time chart.
  Useful for showing program-level improvement to auditors.
- **Sufficiency scoring.** Beyond presence-of-evidence, score each
  covered subcategory by the depth and recency of its supporting
  artifacts. The auditor's existing review judgment, automated.
- **Cross-framework mapping.** Map AI RMF subcategories to NIST 800-53
  controls, ISO/IEC 42001 clauses, and EU AI Act articles so a single
  analyzer run produces evidence cross-referenced to whichever
  framework the customer's audit cycle uses.
- **Dashboard surface.** A Splunk dashboard reading `coverage.json`
  with drilldowns into the source artifacts. The Splunk-side capstone
  to match the portfolio-side capstone.

## Why this is the capstone

The previous seven projects each demonstrate one engineering pattern
applied to one slice of AI security. This project demonstrates the
*compound* — the seven slices integrating into a coherent governance
artifact, the same way Qmulos's product line integrates monitoring +
detection + compliance evidence into a single continuous program. The
candidate behind this portfolio has been doing exactly that for federal
customers for nine years, with traditional SIEM + 800-53. Project 8 is
the proof that the same discipline carries cleanly into AI / LLM
workloads.

That is the portfolio's full thesis. Eight projects, one pipeline,
machine-checkable continuous compliance against NIST AI RMF 1.0.
