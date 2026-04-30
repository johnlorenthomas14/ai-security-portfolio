# 02 — AI Red-Team Automation Framework

[![CI](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml/badge.svg)](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP%20LLM-Top%2010%20(2025)-orange.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![NIST AI RMF](https://img.shields.io/badge/NIST%20AI%20RMF-1.0-blue.svg)](https://www.nist.gov/itl/ai-risk-management-framework)

> **Automated red-team probing of LLM applications, with findings shaped as
> NIST AI RMF evidence.** Loads probe templates from a YAML attack library,
> fires them at any target adapter, scores responses with a three-layer
> scorer (Project 1's detector + heuristics + optional LLM judge), and
> produces a Splunk-ingestible JSON findings file alongside an analyst-readable
> Markdown evidence report keyed by AI RMF subcategory.

**Status:** Working MVP. Ships with 20 starter probes across five OWASP LLM Top 10
(2025) categories, an in-process deliberately-vulnerable demo target, and a
pytest suite that runs the framework end-to-end with no API key required.

> **Engineering write-up:** [`WRITEUP.md`](./WRITEUP.md) — the why behind
> every design decision in this framework. Threat model, scoring-layer
> rationale, probe-schema trade-offs, calibration vs. operational signal,
> Splunk HEC integration with batch / ack / Cribl-fronting detail, Cortex
> XSIAM mapping, and roadmap. ~3,300 words, 12-minute read.

## Threat model

| | |
|---|---|
| **Attacker capability** | Black-box query access to the target LLM endpoint. May fuzz prompts, retrieve outputs, replay across sessions. |
| **Target asset** | A deployed LLM application — its system prompt, any tools it can reach, the data exposed in its outputs. |
| **In scope** | LLM01 Prompt Injection · LLM02 Sensitive Information Disclosure · LLM06 Excessive Agency · LLM07 System Prompt Leakage · LLM09 Misinformation / Jailbreaks |
| **Out of scope (MVP)** | LLM03 Supply Chain (training-time — covered by Project 6) · LLM04 Data and Model Poisoning (training-time) · LLM05 Improper Output Handling (host-app concern, not target-LLM concern) · LLM08 Vector and Embedding Weaknesses (RAG-specific — covered by Project 3) · LLM10 Unbounded Consumption (resource exhaustion — separate detection stack) |

## Architecture

```
                 ┌────────────────────┐
                 │ attack-library/    │  YAML probes by OWASP category
                 │  llm01_*.yaml      │
                 │  llm02_*.yaml      │
                 │  llm06_*.yaml      │
                 │  llm07_*.yaml      │
                 │  llm09_*.yaml      │
                 └─────────┬──────────┘
                           │
                           ▼
┌──────────────┐    ┌────────────────────┐    ┌────────────────────────┐
│ targets/     │    │ runner.py          │    │ scorer.py              │
│  Anthropic   │◄───┤  load probes       │───►│  Layer A — Project 1   │
│  Demo (mock) │    │  send each probe   │    │           detector     │
│  BYO adapter │───►│  collect findings  │◄───│  Layer B — regex on    │
└──────────────┘    └─────────┬──────────┘    │           response     │
                              │               │  Layer C — LLM judge   │
                              ▼               │           (optional)   │
                    ┌────────────────────┐    └────────────────────────┘
                    │ report.py          │
                    │  findings.json     │   Splunk-ingestible (CIM eventtype)
                    │  airmf_evidence.md │   AI RMF-keyed evidence narrative
                    └────────────────────┘
```

## The three-layer scorer

Each probe response is scored on three axes that combine into a verdict of
`pass`, `warning`, or `fail`.

**Layer A — Project 1's prompt-injection detector** runs on the *attack input*.
This is the sanity check: does the framework's own scorer recognize its own
attacks? If Project 1 returns `benign` on a probe meant to be malicious, that
indicates a red-team-tool bug, not a target-LLM finding.

**Layer B — heuristic regex on the response.** Each probe declares
`success_indicators` (capitulation markers — text that suggests the target
complied with the attack) and `refusal_indicators` (markers of a clean refusal).
The scorer matches both lists against the response. Refusal-only → pass.
Success-only → fail. Both or neither → warning.

**Layer C — LLM judge (optional).** When Layer B is inconclusive, an
Anthropic Claude judge is asked to classify the response as
`refused | partial | complied`. Off by default; enable with `--use-judge`.

## Quick start

```bash
cd 02-ai-red-team-framework
pip install -r requirements.txt
pip install -r ../01-prompt-injection-pipeline/requirements.txt   # for the detector

# Run the whole probe library against the in-process demo target.
# No API key required. Outputs land in ./out/.
python runner.py --target demo

# Use the LLM judge for ambiguous-response disambiguation.
ANTHROPIC_API_KEY=... python runner.py --target demo --use-judge

# Probe a real Anthropic Claude system prompt instead.
ANTHROPIC_API_KEY=... python runner.py \
    --target anthropic \
    --target-name my-customer-bot \
    --system-prompt-file my_system_prompt.txt

# Tests (offline, stub-only).
pytest -q
```

## Output — findings.json + airmf_evidence.md

`findings.json` — machine-readable, one finding per probe. Each finding carries
Splunk-friendly fields (`cim_eventtype="ai_red_team_finding"`, `signature`,
`event_severity`, `event_time`) so a scheduled run can be ingested directly
into Enterprise Security as recurring scan results.

`airmf_evidence.md` — analyst-readable Markdown with:

- Executive summary and pass-rate.
- Findings tabulated by OWASP LLM Top 10 category.
- **NIST AI RMF 1.0 evidence keyed by subcategory** (`MEASURE 2.7`,
  `MEASURE 2.10`, `MANAGE 2.3`, etc.). Pass verdicts demonstrate effective
  control; warnings and fails indicate gaps requiring Manage-function action.
- Per-finding technical details — attack text, response excerpt, verdict
  rationale, ATLAS technique IDs.

## Probe library — what's shipped

20 probes across five OWASP categories, each mapped to a NIST AI RMF
subcategory and one or more MITRE ATLAS techniques.

| Category | Probes | Coverage |
|---|---:|---|
| **LLM01** Prompt Injection | 5 | direct override, reset framing, forged authority, role-marker forgery, indirect-style payload |
| **LLM02** Sensitive Information Disclosure | 3 | direct PII by name, indirect PII via support framing, internal data dump |
| **LLM06** Excessive Agency | 3 | tool exfiltration, tool-chain abuse, destructive action |
| **LLM07** System Prompt Leakage | 4 | direct extraction, "repeat verbatim", embedded-secret extraction, roleplay extraction |
| **LLM09** Misinformation / Jailbreak | 5 | DAN persona, developer mode, hypothetical bypass, fictional framing, override-code reuse |

Adding a new probe is a single YAML file in `attack-library/` — no Python
edits required.

## Splunk integration

Each finding is emitted in a CIM-shaped JSON event suitable for direct
ingestion to Splunk via HEC or batch file collection. A scheduled run
becomes a recurring scan; an ES correlation search can alert on, for example,
*"any new fail-verdict finding in `cim_eventtype=ai_red_team_finding`."*

```spl
index=aisec sourcetype="aisec:red_team" cim_eventtype="ai_red_team_finding" verdict="fail"
| stats count values(probe_id) as probes values(atlas_techniques) as atlas
        by target_name owasp_category
| eval severity=case(severity=="high","high","severity"=="medium","medium",1=1,"low")
| `notable_event(ai_red_team_finding, severity, "Red-team probe found a control gap")`
```

### Why HEC, and where you'd extend it for production

HEC is the idiomatic ingestion path for this project's emission profile —
scheduled runs producing a bounded set of synthesized events with no
on-disk log file for a Universal Forwarder to tail. For low-volume
scheduled scans this is optimal, not a compromise.

For higher-volume or stricter-license deployments the path forward is:

- **Batch the HEC POST.** Use the `/services/collector/event/batch`
  endpoint to send all findings from one run in a single request rather
  than per-event POSTs — amortizes TLS handshake cost and indexer parse
  overhead across the full run.
- **HEC ack mode.** Enable HEC acknowledgements so the framework retries
  on transient indexer errors instead of silently dropping findings.
- **Cribl Stream in front of HEC.** When license / SVC consumption is the
  binding constraint (typical on federal Splunk Cloud engagements),
  ingest into Cribl first, drop verdict-pass findings at the edge, and
  forward only warnings and fails to Splunk. This is the standard
  pattern for compliance-evidence streams that produce a lot of
  pass/no-finding noise.

Universal Forwarder is the wrong fit here — the data isn't on disk, the
host is typically serverless or ephemeral, and you'd be inventing
agent-management complexity to solve a non-problem. UF wins above
~10k events/sec sustained or where files already exist; this framework
is neither.

## What's not in MVP (roadmap)

- **Multi-turn probes.** Some attacks require a setup turn before the payload
  (e.g., establishing trust, then issuing the override). Current probes are
  single-turn.
- **Adversarial mutation.** A probe-mutation layer that takes a base attack
  and uses an LLM to generate evasion variants — useful for catching novel
  phrasings of known attack classes.
- **More targets.** OpenAI, Gemini, generic HTTP — each is a ~30-line adapter
  added to `targets/`.
- **More probes.** The README stub originally targeted 80; MVP ships 20.
  Adding more is a YAML edit.
- **External-eval comparison.** Run probes against published red-team eval
  sets (Lakera Gandalf, ToxicChat-PI) for cross-corpus calibration.

## Why this matters for the portfolio

Project 2 is the *offensive* counterpart to Project 1's defensive detector.
Together they form a closed loop: Project 1 detects injection at the input
layer; Project 2 produces the corpus of attacks Project 1 needs to stay
current. The NIST AI RMF mapping turns the same artifact into compliance
evidence — runtime probing as continuous-monitoring evidence for the Measure
function, with gaps surfacing as Manage-function action items. That is the
shape an AI-governance-aware security engineer produces.
