# AI Security Portfolio

[![CI](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml/badge.svg)](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Eight projects translating 9+ years of federal/enterprise SIEM and Splunk
detection-engineering experience into the AI Security Engineer toolkit.
Each project is self-contained, runs offline by default, and maps to
recognized control frameworks (MITRE ATLAS, OWASP LLM Top 10 (2025),
NIST AI RMF 1.0, NIST 800-53 / FedRAMP).

**Live site:** [johnlorenthomas14.github.io/ai-security-portfolio](https://johnlorenthomas14.github.io/ai-security-portfolio/)

> See [`CLAUDE.md`](./CLAUDE.md) for conventions, threat-model template,
> and detector output schema shared across all eight projects.

## The lineup

| # | Project | One-line | Status |
|---|---------|----------|--------|
| 1 | [LLM Prompt Injection Detection Pipeline](./01-prompt-injection-pipeline) | Hybrid heuristic + Claude-judge detector at the LLM input layer. ATLAS-tagged verdicts forwarded to Splunk ES; F1 = 1.000 on shipped eval with CI regression floor. | **Working MVP** |
| 2 | [AI Red-Team Automation Framework](./02-ai-red-team-framework) | Probes any LLM target against OWASP LLM Top 10; three-layer scorer reuses Project 1's detector. JSON findings + AI-RMF Markdown evidence. | **Working MVP** |
| 3 | [RAG Pipeline Security Auditor](./03-rag-security-auditor) | Static corpus scanner — indirect-injection, PII, credentials, sensitivity markers caught at ingestion before they reach a production LLM. | **Working MVP** |
| 4 | [SIEM Correlation Rule Generator for AI Workloads](./04-siem-correlation-generator) | ATLAS-mapped Splunk ES correlation searches and Sigma rules consuming the JSON event shape Projects 1–3 emit. | Spec |
| 5 | [LLM Output Safety & Compliance Monitor](./05-llm-output-compliance-monitor) | FedRAMP-aware serverless output guardrail with hash-chained, Object-Lock audit log. | Spec |
| 6 | [AI Model Supply Chain Risk Scanner](./06-model-supply-chain-scanner) | Pickle / tokenizer / provenance scans for open-source model artifacts; CycloneDX SBOM fragment output. | Spec |
| 7 | [Adaptive Threat Intelligence Summarizer](./07-threat-intel-summarizer) | STIX/TAXII feeds → cited analyst briefs and Splunk notables. | Spec |
| 8 | [NIST AI RMF Compliance Gap Analyzer](./08-nist-ai-rmf-gap-analyzer) | Continuous AI-governance evidence collection. Extends Qmulos Q-Compliance / Q-Audit pattern into AI controls. | Spec |

## What's working today (the three MVPs)

**Project 1** ships a working hybrid prompt-injection detector with a
17-test pytest suite, a 30-row labeled eval set scoring P/R/F1 = 1.000
on the heuristic-only path, GitHub Actions CI enforcing an F1 ≥ 0.85
regression floor, an asciicast demo embedded in the README, and a
2,400-word [engineering write-up](./01-prompt-injection-pipeline/WRITEUP.md).

**Project 2** ships an OWASP-LLM-Top-10-shaped red-team framework with
20 starter probes across five attack categories, a deliberately-vulnerable
demo target that ships zero-warning 20/20 fail verdicts in CI, and a
3,300-word [engineering write-up](./02-ai-red-team-framework/WRITEUP.md)
covering the three-layer scorer, probe-format trade-offs, and the
production-tuning levers for Splunk HEC ingestion (batch endpoint, ack
mode, Cribl-fronting for license-constrained federal deployments).

**Project 3** ships a static corpus scanner with four scanner classes
(indirect-injection, PII, credentials, sensitivity markers), six demo
documents (several intentionally polluted), an 8-test pytest suite, and
a 3,300-word [engineering write-up](./03-rag-security-auditor/WRITEUP.md)
explaining why static-corpus-shape is the right MVP and where NER-based
PII and embedding-similarity scans fit on the roadmap.

The three MVPs intentionally compound: Project 3 catches injection
payloads and PII at corpus ingestion; Project 1 catches what gets through,
at runtime; Project 2 generates the attack corpus that keeps Project 1's
eval current. Defense-in-depth across the full RAG security chain, all
emitting CIM-aligned JSON events to the same Splunk ingestion pipeline,
all tagged with MITRE ATLAS technique IDs and NIST AI RMF subcategories
so the same artifact serves both SOC and GRC audiences.

## Quick start

```bash
# Clone
git clone https://github.com/johnlorenthomas14/ai-security-portfolio
cd ai-security-portfolio

# Project 1 demo (offline, no API key needed)
cd 01-prompt-injection-pipeline
pip install -r requirements.txt
./demo.sh

# Project 2 — fire 20 probes at the in-process vulnerable demo target
cd ../02-ai-red-team-framework
pip install -r requirements.txt
python3 runner.py --target demo

# Project 3 — audit the shipped polluted demo corpus
cd ../03-rag-security-auditor
pip install -r requirements.txt
python3 auditor.py --corpus corpus/demo
```

Every project ships its own `demo.sh` for asciinema recording / screen
capture, its own `pytest` suite that runs offline, and a CIM-shaped
JSON output ready for Splunk HEC ingestion.

## Why this shape

Each project pairs an AI-security capability with a SOC-team output: a
detection rule, a notable event, an analyst summary, a compliance artifact.
That's deliberate — the portfolio reads as detection engineering that
happens to target AI workloads, not as ML demos that mention security.

The output discipline is consistent across projects:

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
- **Cortex XSIAM mapping** documented in every README. Detection
  content authored once, portable across SIEM stacks.

## Author

[John Thomas](https://www.linkedin.com/in/john-thomas-751578130) — Principal
Splunk Consultant, 9+ years federal SIEM (IRS, federal health, federal
oversight) and Fortune-500 enterprise detection engineering. Currently
extending the same NIST 800-53 / FedRAMP detection-engineering discipline
into AI / LLM security.
