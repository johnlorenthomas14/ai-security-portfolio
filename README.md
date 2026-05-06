# AI Security Portfolio

[![CI](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml/badge.svg)](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Nine projects translating 9+ years of federal/enterprise SIEM and Splunk
detection-engineering experience into a complete AI Security Engineer
toolkit. Each project is self-contained, runs offline by default, and
maps to recognized control frameworks (MITRE ATLAS, OWASP LLM Top 10
(2025), NIST AI RMF 1.0, NIST 800-53 / FedRAMP).

**Live site:** [johnlorenthomas14.github.io/ai-security-portfolio](https://johnlorenthomas14.github.io/ai-security-portfolio/)

> See [`CLAUDE.md`](./CLAUDE.md) for conventions, threat-model template,
> and the detector output schema shared across the portfolio.

## The lineup

| # | Project | One-line | Status |
|---|---------|----------|--------|
| 1 | [LLM Prompt Injection Detection Pipeline](./01-prompt-injection-pipeline) | Hybrid heuristic + Claude-judge detector at the LLM input layer. ATLAS-tagged verdicts forwarded to Splunk ES; F1 = 1.000 on shipped eval with CI regression floor. | **Working MVP** |
| 2 | [AI Red-Team Automation Framework](./02-ai-red-team-framework) | Probes any LLM target against OWASP LLM Top 10; three-layer scorer reuses Project 1's detector. JSON findings + AI-RMF Markdown evidence. | **Working MVP** |
| 3 | [RAG Pipeline Security Auditor](./03-rag-security-auditor) | Static corpus scanner — indirect-injection, PII, credentials, sensitivity markers caught at ingestion before they reach a production LLM. | **Working MVP** |
| 4 | [SIEM Correlation Rule Generator for AI Workloads](./04-siem-correlation-generator) | One canonical YAML rule → three SIEM-native outputs (Splunk ES correlation searches, Sigma rules, Cortex XSIAM XQL). Auto-generated AI-RMF coverage map. | **Working MVP** |
| 5 | [LLM Output Safety & Compliance Monitor](./05-llm-output-compliance-monitor) | Runtime output guardrail with PII / secrets / classification / policy filters. Hash-chained, tamper-evident audit log — the FedRAMP-flavored integrity-evidence pattern. | **Working MVP** |
| 6 | [AI Model Supply Chain Risk Scanner](./06-model-supply-chain-scanner) | Pickle-opcode disassembly without execution + provenance + risky-deps scan of model artifacts; CycloneDX 1.5 SBOM fragment output. | **Working MVP** |
| 7 | [Adaptive Threat Intelligence Summarizer](./07-threat-intel-summarizer) | STIX 2.1 → cited analyst briefs + Splunk notables. Citation verifier rejects hallucinated references — every claim Claude writes is bound to a real bundle object ID. | **Working MVP** |
| 8 | [NIST AI RMF Compliance Gap Analyzer](./08-nist-ai-rmf-gap-analyzer) | Reads outputs from Projects 1–7, maps each finding to its AI RMF subcategory, produces continuous-monitoring evidence + gap report. The Qmulos Q-Compliance / Q-Audit pattern, applied to AI governance. | **Working MVP** |
| 9 | [Autonomous SOC Analyst Agent](./09-autonomous-soc-analyst) | Agentic tool-use loop with six analyst tools, defended at the input layer by Project 1's detector. 8-case eval suite at 100% pass rate, CI-gated at 75% floor. | **Working MVP** |

## The closed-loop pipeline

Nine projects across three deployment phases, all sharing an event vocabulary, a taxonomy (OWASP LLM Top 10 / MITRE ATLAS / NIST AI RMF), and a Splunk ingestion story:

```
                 PRE-DEPLOYMENT                        RUNTIME                       GOVERNANCE / OPERATIONS
            ┌────────────────────────┐         ┌────────────────────────┐        ┌────────────────────────┐
            │ 06 — Model Supply      │         │ 01 — Prompt Injection  │        │ 04 — SIEM Correlation  │
            │      Chain Scanner     │         │      Detection         │        │      Rule Generator    │
            │   (pickle / SBOM)      │         │   (input layer)        │        │   (Splunk + Sigma +    │
            │                        │         │                        │        │    XSIAM content)      │
            ├────────────────────────┤         ├────────────────────────┤        ├────────────────────────┤
            │ 03 — RAG Pipeline      │         │ 05 — Output Safety &   │        │ 07 — Threat-Intel      │
            │      Security Auditor  │   ───►  │      Compliance        │  ───►  │      Summarizer        │
            │   (static corpus       │         │      Monitor           │        │   (STIX → notables)    │
            │    scanning)           │         │   (output layer +      │        │                        │
            │                        │         │    hash-chained log)   │        ├────────────────────────┤
            └────────────────────────┘         ├────────────────────────┤        │ 08 — NIST AI RMF       │
                                               │ 02 — AI Red-Team       │        │      Gap Analyzer      │
                                               │      Framework         │        │   (continuous-evidence │
                                               │   (adversarial         │        │    capstone)           │
                                               │    validation)         │        │                        │
                                               ├────────────────────────┤        ├────────────────────────┤
                                               │ 09 — Autonomous SOC    │        │                        │
                                               │      Analyst Agent     │ ◄──────│  (consumes notables    │
                                               │   (defended by P1)     │        │   from P4 + P7)        │
                                               └────────────────────────┘        └────────────────────────┘
```

The compounding interview line, in one paragraph:

> *"Project 6 audits the model artifact pre-deployment. Project 3 audits the corpus pre-retrieval. Project 1 detects injection at runtime. Project 5 guards the output layer with hash-chained tamper-evident audit logs. Project 2 generates the adversarial corpus that keeps Project 1's eval set honest. Project 7 produces citation-verified threat-intel briefs from STIX bundles. Project 4 turns every project's findings into deployable Splunk ES, Sigma, and Cortex XSIAM correlation content. Project 8 reads the whole pipeline's output and produces NIST AI RMF continuous-monitoring evidence. Project 9 is an autonomous SOC analyst agent that defends its own input layer using Project 1 — closed-loop AI-security as defense-in-depth."*

## Engineering write-ups

Three projects ship long-form engineering write-ups (each ~3,000 words):

- [Project 1 — Prompt Injection Detection Pipeline](./01-prompt-injection-pipeline/WRITEUP.md) — threat model, why hybrid heuristic + LLM, rule-by-rule rationale, eval methodology, F1 = 1.000 honest disclosure, Splunk ES integration, Cortex XSIAM mapping, roadmap.
- [Project 2 — AI Red-Team Automation Framework](./02-ai-red-team-framework/WRITEUP.md) — three-layer scorer architecture, probe-format trade-offs, calibration vs. operational signal, Splunk HEC integration with batch / ack / Cribl detail.
- [Project 3 — RAG Pipeline Security Auditor](./03-rag-security-auditor/WRITEUP.md) — why static-corpus shape vs. live RAG probing, scanner design trade-offs, regex-vs-NER false-positive trade-off, federal-compliance angle.

## Quick start

```bash
# Clone
git clone https://github.com/johnlorenthomas14/ai-security-portfolio
cd ai-security-portfolio

# Project 1 — prompt-injection detector
cd 01-prompt-injection-pipeline && pip install -r requirements.txt && ./demo.sh

# Project 2 — red-team probes against the in-process vulnerable demo target
cd ../02-ai-red-team-framework && pip install -r requirements.txt && python3 runner.py --target demo

# Project 3 — audit the shipped polluted demo corpus
cd ../03-rag-security-auditor && pip install -r requirements.txt && python3 auditor.py --corpus corpus/demo

# Project 4 — generate detection content for three SIEMs from one canonical rule library
cd ../04-siem-correlation-generator && pip install -r requirements.txt && python3 generator.py

# Project 5 — replay LLM output samples through the compliance monitor
cd ../05-llm-output-compliance-monitor && pip install -r requirements.txt && python3 monitor.py --corpus samples/bad_outputs.jsonl --audit-log out/audit.jsonl

# Project 6 — scan a model directory for pickle / provenance / dependency risk
cd ../06-model-supply-chain-scanner && pip install -r requirements.txt && python3 scanner.py --model samples/demo_model

# Project 7 — generate cited threat-intel briefs offline
cd ../07-threat-intel-summarizer && pip install -r requirements.txt && python3 summarizer.py --offline

# Project 8 — capstone: read everything Projects 1–7 produced and emit a NIST AI RMF coverage report
cd ../08-nist-ai-rmf-gap-analyzer && pip install -r requirements.txt && python3 analyzer.py

# Project 9 — autonomous SOC analyst agent over notable events
cd ../09-autonomous-soc-analyst && pip install -r requirements.txt && python3 analyst.py
```

Every project ships its own `demo.sh` for asciinema recording / screen
capture, its own `pytest` suite that runs offline, and CIM-shaped JSON
output ready for Splunk HEC ingestion.

## Why this shape

Each project pairs an AI-security capability with a SOC-team output: a
detection rule, a notable event, an analyst summary, a compliance
artifact. That's deliberate — the portfolio reads as detection
engineering that happens to target AI workloads, not as ML demos that
mention security.

The output discipline is consistent across all nine projects:

- **Threat model** up front in every README — attacker capability,
  target asset, in-scope, out-of-scope. Scope honesty is the price of
  being trusted as a control.
- **Measurable detector** with a regression-tested eval where applicable.
  CI enforces a numeric floor; performance regressions break the build.
- **CIM-aligned JSON** as the primary output. Drop-in Splunk HEC
  ingestion, no parsing required at the indexer.
- **AI-RMF-aligned Markdown** as the secondary output. The same
  detection content doubles as continuous-monitoring evidence for the
  Measure and Manage functions of NIST AI RMF.
- **Cortex XSIAM mapping** documented in the cross-platform projects.
  Detection content authored once, portable across SIEM stacks.
- **Offline-by-default operation.** Every project's CI run is
  deterministic, reproducible, and requires no API key — the regression
  guard is real, not aspirational.

## CI

Eighteen jobs per push (9 projects × Python 3.11 / 3.12). Every project
has at least:

- A `pytest -q` step that runs the full test suite offline.
- An end-to-end demo run that exercises the project's CLI and verifies
  the expected output artifacts are produced.

For the projects that have measurable detectors (Projects 1, 9), CI
also enforces a regression floor — the build breaks if accuracy or
pass-rate drops below threshold.

## Author

[John Thomas](https://www.linkedin.com/in/john-thomas-751578130) —
Principal Splunk Consultant, 9+ years federal SIEM (IRS, federal
health, federal oversight) and Fortune-500 enterprise detection
engineering. Currently extending the same NIST 800-53 / FedRAMP
detection-engineering discipline into AI / LLM security.
