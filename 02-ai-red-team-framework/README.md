# 02 — AI Red-Team Automation Framework

Automated red-team probing of LLM applications against the **OWASP Top 10
for LLM Applications (2025)**, with each finding mapped to a **NIST AI RMF
1.0** subcategory so the output doubles as a control-evidence artifact.

**Status:** Spec / scaffold — populated next.

## Threat model

| | |
|---|---|
| **Attacker capability** | Black-box query access to the target LLM endpoint (chat or tool-using agent). May fuzz prompts, retrieve outputs, and replay across sessions. |
| **Target asset** | The deployed LLM application: its system prompt, its tools, its outputs, and the data it can reach. |
| **In scope** | LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector & Embedding Weaknesses (lite), LLM09 Misinformation, LLM10 Unbounded Consumption. |
| **Out of scope** | White-box weight-level attacks, training-time poisoning. Project 6 covers the supply-chain side. |

## Architecture

```
attack-library/      ── YAML probe families (LLM01 ... LLM10)
runner.py            ── orchestrates: target → probe → judge → report
judges/              ── per-attack verdict heuristics + Claude judge
mappings/
  owasp_to_atlas.yml ── OWASP LLM Top 10 → MITRE ATLAS techniques
  atlas_to_airmf.yml ── ATLAS → NIST AI RMF (Govern/Map/Measure/Manage)
report/
  findings.json
  airmf_evidence.md  ── auto-generated control-evidence narrative
```

The runner targets any HTTP endpoint that takes a string prompt and returns
a string completion (a small `targets/` shim normalizes Anthropic, OpenAI,
and bring-your-own).

## Deliverables

1. ~80 reusable probes across LLM01–LLM10, each with a JSON-schema
   verdict + the OWASP/ATLAS/AI-RMF mapping baked in.
2. CLI: `python runner.py --target config.yml --suite owasp-llm-top10`.
3. Output: a `findings.json` per run + an AI RMF evidence report keyed
   by subcategory (`MEASURE 2.7`, `MANAGE 2.3`, etc.).

## Splunk / SOC tie-in

Every finding includes a `cim_eventtype="ai_red_team_finding"` event so a
scheduled run becomes a recurring scan. The roadmap includes a Splunk app
with a "AI Red-Team Coverage" dashboard pivoted by OWASP category, ATLAS
technique, and AI RMF subcategory.

## Why this matters for the portfolio

This is the offensive counterpart to Project 1's defensive detector. The
AI RMF mapping is the federal/compliance angle that pairs naturally with
the user's Qmulos / NIST 800-53 background.
