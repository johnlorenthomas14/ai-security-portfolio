# 09 — Autonomous SOC Analyst Agent

[![CI](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml/badge.svg)](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Agent eval](https://img.shields.io/badge/agent%20eval-floor%200.75-blueviolet.svg)](#the-eval-suite)
[![Post-sprint](https://img.shields.io/badge/portfolio-Project%209-purple.svg)](../README.md)

> **Autonomous SOC analyst running an agentic tool-use loop over notable
> events emitted by Projects 4 and 7. Defends its own input layer with
> Project 1's prompt-injection detector — the agent never acts
> autonomously on attacker-controlled text. Six tools (Splunk search,
> IOC enrichment, MITRE ATLAS lookup, STIX lookup, escalate-to-human,
> summarize), a deterministic offline stub LLM client, an 8-case
> eval suite with golden triage outcomes, and a pass-rate floor
> enforced in CI.** This is the first project in the portfolio that
> demonstrates *agent-builder* skill — and the architectural pattern
> the rest of the AI security industry is rapidly converging on.

**Status:** Working MVP. Ships with the six tools, the input guard
(Project 1 integration), the deterministic stub client, the agent
loop with three termination conditions, the eval set + scorer, an
analyst CLI, a 17-test pytest suite, and a CI job that runs both the
demo corpus and the eval suite against the agent on every push.

## Threat model

| | |
|---|---|
| **Attacker capability** | Two distinct surfaces. (1) **Notable-content injection** — the agent ingests notable events whose own text fields might contain attacker-controlled prompt-injection payloads (an injection notable's `src_input_excerpt` literally is an injection attempt). (2) **Tool-output injection** — tool results returned to the agent (e.g., a Splunk search hit, a STIX object description) might also contain attacker-controlled text. |
| **Target asset** | The agent's instruction integrity, the SOC's downstream actions on the agent's recommendations, and any tools the agent has authority to invoke. |
| **In scope** | Input-guarding all notable text fields with Project 1's detector before the agent loop starts; deterministic tool dispatch (LLM never executes Python); explicit max-iteration ceiling; safe-default tool (`escalate_to_human`) for any condition the agent should not handle autonomously. |
| **Out of scope (MVP)** | Tool-output injection scanning — tool results currently feed back into the agent's context without being re-scanned. The fix is straightforward (run InputGuard over tool outputs too) and is the highest-priority roadmap item. Live LLM tool-use against a real Anthropic API — the MVP uses a deterministic stub for offline / CI runs. |

## Architecture

```
            notable event (from Projects 4, 7, or any source)
                              │
                              ▼
            ┌────────────────────────────────────┐
            │ runtime/InputGuard                 │   uses Project 1's
            │   scan every text field            │   PromptInjectionDetector
            │   → InputGuardResult(tainted=...)  │   in heuristic-only mode
            └────────────────┬───────────────────┘
                             │
                             ▼
            ┌────────────────────────────────────┐
            │ SOCAnalystAgent.triage(notable)    │   tool-use loop
            │   if tainted → escalate-only mode  │
            └────────────────┬───────────────────┘
                             │
                ┌────────────┴────────────┐
                ▼                         ▼
        StubAgentClient              (live Claude — roadmap)
        deterministic policy
                │
                ▼
            chooses one of six tools per iteration:
            ┌─────────────────────────────────────────────────┐
            │  splunk_search   ioc_enrichment  atlas_lookup   │
            │  stix_lookup     escalate (term)  summarize     │
            │                                          (term) │
            └─────────────────────────────────────────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │  TriageReport            │   verdict, audit trail,
                │   verdict, tool_calls,   │   final summary or
                │   final_summary,         │   escalation
                │   final_escalation       │
                └──────────────────────────┘
```

Termination conditions:

- **`summarize` called** → `verdict = triaged` (or `input_tainted_triaged` if guard fired).
- **`escalate_to_human` called** → `verdict = escalate` (or `input_tainted_escalated`).
- **`max_iterations` exceeded** → `verdict = max_iterations_exceeded` (treated as escalation).

## The six tools

**`splunk_search`** — runs simple `field=value` filters against a synthetic Splunk-like event store (ships with a JSONL of representative `ai_prompt_injection` events). Mock implementation; production would dispatch to the real Splunk REST API. Useful for pulling related events around the same user / app / src_ip.

**`ioc_enrichment`** — auto-detects IOC type (IPv4, domain, SHA256, URL) and returns deterministic synthetic enrichment (reputation, geo, ASN). RFC1918 IPs return `verdict=internal`; TEST-NET-3 IPs return `verdict=malicious` (so the eval set has a known-bad path); attacker-domain patterns also return `malicious`. Production would call out to VirusTotal / GreyNoise / OTX.

**`atlas_lookup`** — looks up MITRE ATLAS technique metadata by ID (`AML.T0051`, `AML.T0054`, `AML.T0010`, etc.). Ships with a small in-process catalog covering the techniques the rest of the portfolio actually tags with. Production would fetch the live catalog from atlas.mitre.org.

**`stix_lookup`** — searches Project 7's STIX bundles for objects by ID or by indicator-value substring. Useful for tying a notable's IOCs back to a known campaign / threat-actor / vulnerability context. Reads the actual JSON bundles shipped with Project 7.

**`escalate_to_human`** — terminates triage with `verdict=escalate`. The agent's safe-default exit. Used for situations requiring human authorization (blocking actions), notables flagged by the input guard, or anything outside the agent's stated authority.

**`summarize`** — terminates triage with `verdict=triaged`. The agent's clean-completion exit. Produces an analyst-readable summary + key-evidence list + recommended action.

## The input guard — closing the loop on AI-security-as-defense-in-depth

This is the architectural pattern that makes Project 9 a portfolio
capstone rather than a generic agent demo.

The notable event the agent ingests can itself contain attacker-
controlled text. An `ai_prompt_injection` notable's `src_input_excerpt`
field is *literally* an injection attempt. If the agent feeds that
text into its own tool-use prompt without first marking it as
untrusted, the agent's own behavior can be hijacked by content the
SOC originally captured because Project 1 flagged it as malicious.

**`runtime/InputGuard`** scans every recognized text field of every
notable through Project 1's `PromptInjectionDetector` (heuristic-only
mode, no API key, deterministic). If anything fires, the notable is
marked `tainted`, and the stub agent client switches to escalate-only
mode — the agent will only call `escalate_to_human`, never any tool
that lets attacker text drive autonomous action.

That pattern — *the agent's own input layer is defended by the
portfolio's own runtime detector* — is the closed-loop defense-in-depth
demonstration the rest of the portfolio is built around.

## The deterministic stub client

A real Claude tool-use call is non-deterministic, takes ~5–15 seconds
per iteration, and requires an API key. None of those properties are
compatible with a CI regression check or with a deterministic eval
suite.

**`StubAgentClient`** is a small policy table that picks tools
deterministically based on the notable's structure and the agent's
accumulated context:

1. Tainted input → escalate immediately.
2. Splunk search around user + app for related events.
3. IOC enrichment on the source IP / indicator.
4. ATLAS lookup for any tagged technique.
5. STIX lookup for the indicator.
6. Decide: malicious enrichment OR malicious notable verdict → escalate.
   Otherwise → summarize.

The stub never substitutes for a real LLM in production. It exists so
the agent's full surface — loop, input guard, tool dispatch, verdict
handling — can be regression-tested without spending tokens. The eval
suite measures the stub against golden outcomes; CI enforces a
pass-rate floor.

## The eval suite

`eval/test_notables.jsonl` ships 8 hand-crafted test notables, each
with golden expectations for:

- **`expected_verdict`** — what the final report verdict must be.
- **`expected_tools_called`** — exact-match tools-called sequence (or `expected_tools_called_min` for at-least-these-tools).
- **`expected_input_tainted`** — whether the input guard should fire.

`eval/scorer.py` runs the agent against every case and produces three
metrics:

- `verdict_accuracy` — fraction of cases where actual verdict matches expected.
- `tool_precision` — fraction where the tools-called sequence matches.
- `input_guard_accuracy` — fraction where the guard's tainted-flag matches expectation.

A case "passes" when all three axes match. The `analyst.py --eval`
command exits non-zero unless the pass-rate clears `--eval-pass-floor`
(default 0.75). CI enforces that floor on every push.

## Quick start

```bash
cd 09-autonomous-soc-analyst
pip install -r requirements.txt
pip install -r ../01-prompt-injection-pipeline/requirements.txt   # for the input guard

# Run the agent over the demo notables
python3 analyst.py

# Output structure
ls out/
#   reports/    triage_audit.json

# Inspect one of the triage reports
ls out/reports/

# Run the eval suite — exits non-zero if pass rate < 75%
python3 analyst.py --eval

# Tests (offline)
pytest -q
```

## Output

`out/reports/<n>-<notable_id>.md` — analyst-readable Markdown report per
notable. Sections: verdict header, input-guard findings (if any),
summary or escalation block, full audit trail of every tool call.

`out/triage_audit.json` — machine-readable aggregate. Run metadata,
serialized reports for every notable processed, full tool-call audit
trails.

`out/eval_results.json` (when `--eval` is used) — the eval scorer's
output. Per-case verdict / tool / input-guard agreement, plus the three
aggregate metrics and pass-rate.

## What's not in MVP (roadmap)

- **Tool-output input-guarding.** Tool results currently feed back into
  the agent's context without re-scanning. A malicious STIX object
  description or a poisoned Splunk event field could carry an injection
  payload into the agent's loop. Fix: run `InputGuard` over every tool
  result before adding it to history. Simple to implement; the highest-
  priority roadmap item.
- **Live Anthropic tool-use client.** The MVP uses the stub client for
  both offline and online modes. Wiring up real Anthropic tool-use
  (`tools=` parameter on `messages.create`) is straightforward; the
  decoupled `client.decide()` interface is designed for it. Worth
  doing once the eval suite has more cases to keep behavior stable.
- **Multi-turn / multi-notable conversations.** The current agent
  triages one notable at a time. A natural extension: the agent
  recognizes when two notables are part of the same campaign and
  produces a joined triage report. Requires a state layer beyond the
  current single-notable scope.
- **Output safety filter.** Wire Project 5's output compliance monitor
  into the report-emit path. The agent's summary text is LLM-generated
  content (when running on real Claude) and should pass through the
  same PII / classification / policy filters runtime LLM responses do.
- **More eval cases.** 8 cases is enough to demonstrate the pattern.
  Production deployment needs 50–100 cases covering each notable type
  and edge condition (escalation timing, tool-call ordering,
  multi-finding aggregation, etc.).

## Why this matters for the portfolio

Projects 1–8 demonstrate scanner / detector / generator / governance
patterns applied to AI security. Project 9 demonstrates the
agent-builder pattern — the architectural shape the rest of the
industry is rapidly converging on for SOC autonomy, and the one with
the highest multiplier on per-engineer leverage in 2026.

The differentiator is the closed-loop integration: this isn't a
greenfield agent demo. The agent's input layer is defended by the
portfolio's own runtime detector (Project 1). Its tool surface
includes lookup against the portfolio's own threat-intel bundles
(Project 7). Its IOC enrichment recognizes the same attacker
infrastructure the portfolio's other projects emit findings about.
The agent isn't just *an* agent — it's an agent that *knows about
and uses the rest of the portfolio*.

That self-referential closed loop is the portfolio's full thesis:
nine projects across the AI security pipeline, all sharing an event
vocabulary, a taxonomy, a Splunk integration story, and now an
autonomous-analyst layer that consumes the rest. Detection
engineering meets agent engineering, with federal-compliance-grade
evidence flowing through the whole pipeline. That's the artifact
this portfolio set out to demonstrate.
