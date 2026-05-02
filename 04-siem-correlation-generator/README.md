# 04 — SIEM Correlation Rule Generator for AI Workloads

[![CI](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml/badge.svg)](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE%20ATLAS-mapped-red.svg)](https://atlas.mitre.org/)
[![Sigma](https://img.shields.io/badge/Sigma-rules-green.svg)](https://sigmahq.io/)

> **One canonical YAML rule → three SIEM-native outputs.** Consumes the
> JSON event shapes Projects 1, 2, and 3 emit. Generates Splunk ES
> correlation searches (savedsearches.conf format), Sigma rules
> (cross-platform), and Cortex XSIAM XQL queries from a single canonical
> rule definition per detection. Detection content authored once, deployed
> to whichever SIEM the customer runs.

**Status:** Working MVP. Ships with 8 starter rules covering all three
upstream-project event shapes, three platform-native generators, an
auto-generated coverage map keyed by OWASP / ATLAS / AI RMF, an 8-test
pytest suite, and a CI job that regenerates the entire content set on
every push.

## Why this project

Projects 1, 2, and 3 produce CIM-aligned JSON events. Without correlation
content, those events are just rows in a SIEM index — analysts have to
write the searches themselves to act on them. Project 4 closes that loop
by shipping pre-authored content that turns the events into notable
events automatically.

The interesting design choice is the *one canonical rule, three outputs*
shape. Most detection-content projects pick one platform (usually Splunk)
and ship platform-specific rules. That ties the content to the platform.
This project authors detection logic in a SIEM-agnostic YAML schema and
generates the platform output, so the same rule library deploys to any
of three SIEM stacks today and is one ~30-line generator file away from
deploying to a fourth. That portability matters in real federal and
enterprise environments where the SIEM stack is rarely a clean single
choice.

## Architecture

```
templates/                       ─── canonical YAML rules (SIEM-agnostic)
  AIPI-001-malicious-prompt-injection.yaml
  AIPI-002-suspicious-injection-burst.yaml
  AIPI-003-tool-abuse-attempt.yaml
  AIRT-001-red-team-fail-finding.yaml
  AIRT-002-system-prompt-leakage.yaml
  AIRT-003-jailbreak-persona-success.yaml
  AIRG-001-corpus-credential-leak.yaml
  AIRG-002-corpus-classification-spillage.yaml
       │
       ▼
┌─────────────────────────────────┐
│  generator.py                   │  loads every YAML, runs each generator
│   load_rules → emit_all         │
└──────────────┬──────────────────┘
               │
   ┌───────────┼─────────────────┐
   ▼           ▼                 ▼
┌──────────┐ ┌──────────┐  ┌─────────────────┐
│ SplunkES │ │ Sigma    │  │ Cortex XSIAM    │
│ Generator│ │ Generator│  │ Generator       │
└──────────┘ └──────────┘  └─────────────────┘
   │           │                 │
   ▼           ▼                 ▼
out/splunk_es/  out/sigma/  out/cortex_xsiam/
  AIPI-001.conf  AIPI-001.yml   AIPI-001.xql
  ...             ...            ...
                  out/coverage_map.md
```

Each generator implements `RuleGenerator.render(rule) -> str` plus a
filename function. Adding a new SIEM (e.g., Microsoft Sentinel KQL,
Elastic EQL) is one new file in `rules/` plus one line in
`generator.py`'s generator list — no canonical-rule changes needed.

## The canonical rule schema

Every YAML in `templates/` follows the same structure:

```yaml
id: AIPI-001
name: Malicious Prompt Injection Detected
description: |
  Free-form context for the analyst.
source_index: aisec
sourcetype: aisec:prompt_injection
event_type: ai_prompt_injection      # CIM eventtype emitted by Project 1
severity: high
mitre_atlas: [AML.T0051]
owasp_llm: LLM01
airmf: MEASURE 2.7
condition:
  field: verdict
  operator: equals                   # equals | in | gte | gt | contains
  value: malicious
aggregation:
  group_by: [user, app]
  threshold_count: 1
  window: 1h
response:
  notable_event: true
  drilldown_field: src_input_excerpt
  recommended_action: |
    Free-form analyst playbook text.
```

The schema is deliberately small — fields name *what* the rule looks for,
not how a specific platform expresses it. Each generator translates the
canonical condition + aggregation + response into its target's native
query language.

## The 8 starter rules

| Rule | Source event | OWASP | ATLAS | Severity |
|---|---|---|---|---|
| `AIPI-001` Malicious Prompt Injection Detected | Project 1 | LLM01 | AML.T0051 | high |
| `AIPI-002` Suspicious Injection Burst from Single User | Project 1 | LLM01 | AML.T0051, T0054 | medium |
| `AIPI-003` LLM Tool-Abuse Attempt (Credentials Targeted) | Project 1 | LLM06 | AML.T0051, T0024 | critical |
| `AIRT-001` Red-Team Probe Identified Capitulation | Project 2 | LLM01 | AML.T0051, T0054 | high |
| `AIRT-002` System Prompt Leakage Confirmed | Project 2 | LLM07 | AML.T0051 | high |
| `AIRT-003` Jailbreak Persona Adoption Confirmed | Project 2 | LLM09 | AML.T0054 | high |
| `AIRG-001` Credentials Detected in RAG Corpus Document | Project 3 | LLM02 | AML.T0024 | critical |
| `AIRG-002` Classification Marker Spillage in RAG Corpus | Project 3 | LLM02 | AML.T0024 | critical |

Adding a new rule is one YAML file. The generator picks it up
automatically.

## Quick start

```bash
cd 04-siem-correlation-generator
pip install -r requirements.txt

# Generate detection content for all three platforms
python3 generator.py

# Output structure
ls out/
#   splunk_es/    sigma/    cortex_xsiam/    coverage_map.md

# Inspect a generated Splunk ES correlation search
cat out/splunk_es/AIPI-003.conf

# Inspect the same rule as a Sigma rule
cat out/sigma/AIPI-003.yml

# Inspect the same rule as Cortex XSIAM XQL
cat out/cortex_xsiam/AIPI-003.xql

# Tests (offline)
pytest -q
```

## Splunk integration

The Splunk ES output is a `savedsearches.conf` stanza per rule, ready to
drop into a content pack:

```
[Malicious Prompt Injection Detected]
description = Fires on any malicious-verdict event from the Project 1 ...
search = index=aisec sourcetype="aisec:prompt_injection" cim_eventtype="ai_prompt_injection" verdict="malicious" | stats count by user, app | where count >= 1
dispatch.earliest_time = -1h
enableSched = 1
cron_schedule = */5 * * * *
action.notable = 1
action.notable.param.severity = high
action.notable.param.drilldown_name = Pivot on src_input_excerpt
action.notable.param.drilldown_search = index=aisec sourcetype="aisec:prompt_injection" src_input_excerpt="$result.src_input_excerpt$"
```

Drop the generated `.conf` files into your ES content pack's
`savedsearches.conf`, package, deploy. No additional translation needed.

## Cortex XSIAM integration

Each rule emits an `.xql` file with a metadata header (rule ID, severity,
OWASP / ATLAS / AI RMF tags) followed by the XQL correlation query:

```
// rule_id: AIPI-003
// owasp: LLM06
// atlas: AML.T0051, AML.T0024
// airmf: MANAGE 2.3

dataset = aisec_prompt_injection
| filter _time >= to_timestamp(current_time() - 86400)
| filter cim_eventtype = "ai_prompt_injection"
| filter signals contains "PI-008"
| comp count() as event_count, values(atlas_techniques) as atlas, values(severity) as severities by user, app
| filter event_count >= 1
| alter alert_severity = "critical"
```

Paste the body into a new XSIAM correlation rule. The metadata header
documents the rule's mapping for review.

## Sigma — cross-platform portability

Sigma rules are the cross-platform detection-content format. A Sigma
rule can be converted via `sigmac` or `pySigma` to Elastic EQL,
Microsoft Sentinel KQL, CrowdStrike, Chronicle, and many others. Shipping
Sigma alongside Splunk and XSIAM means the rule library extends to any
SIEM with Sigma support, even if no first-class generator exists in this
project yet.

## What's not in MVP (roadmap)

- **Microsoft Sentinel KQL generator.** ~30-line file in `rules/`,
  parallel to the existing three. Sentinel is the obvious fourth target
  for federal customers.
- **Elastic EQL generator.** Same shape, different syntax.
- **LLM-based rule synthesizer.** A `rules/synthesizer.py` that takes a
  free-form attack description plus an event sample and produces a
  canonical YAML rule via Claude. Useful when you need a *new* detection
  rather than rendering existing ones across platforms. The architecture
  supports this trivially — synthesizer-output is just a new YAML file.
- **Rule-content quality gate.** A linter that validates each rule's
  generated SPL/Sigma/XQL with a syntax checker (`splunk btool`,
  `sigma-cli check`, an XQL parser) before emission.
- **More starter rules.** 8 covers the foundational detections; a
  production library would have 30–50 across all event categories.

## Why this matters for the portfolio

Projects 1–3 produce events. Project 4 turns those events into deployed
SIEM content. Together they form a complete detection-engineering
pipeline for AI workloads — emit events, correlate them, alert on them,
deploy that content across the team's SIEM stack. The same canonical
rule library deploys to whichever platform the customer runs, which is
exactly the portability shape federal and Fortune-500 customers need
when their SIEM stack is heterogeneous.

The single canonical-rule schema is also where the AI-governance angle
becomes concrete. Every rule carries OWASP, MITRE ATLAS, and NIST AI RMF
tags as first-class fields. The `coverage_map.md` output rolls those up
into a per-OWASP / per-AI-RMF table — *"these eight rules provide
detection coverage for LLM01, LLM02, LLM06, LLM07, LLM09 with measurable
evidence flowing to MEASURE 2.7, MEASURE 2.10, MANAGE 2.3, GOVERN 1.3."*
That is the kind of mapping a federal AI governance program needs to
file under continuous monitoring, and it is generated automatically
from the same artifacts the SOC uses for detection. One source of truth,
two audiences.
