# Prompt Injection Detection — Engineering Write-up

**Project:** [LLM Prompt Injection Detection Pipeline](./README.md)
**Author:** [John Thomas](https://www.linkedin.com/in/john-thomas-751578130) — Principal Splunk Consultant; 9+ years federal SIEM and detection engineering.
**Repo:** [github.com/johnlorenthomas14/ai-security-portfolio](https://github.com/johnlorenthomas14/ai-security-portfolio) · **Demo:** [asciinema cast](https://asciinema.org/a/7D9hsPUdsK8lxpbj)

> A SOC-shaped prompt-injection detector that pairs deterministic heuristics with an LLM judge, tags every verdict with MITRE ATLAS technique IDs, and emits CIM-aligned events ready to forward to Splunk Enterprise Security. The included 30-row eval scores P/R/F1 = 1.000 on the heuristic-only path, and CI enforces an F1 ≥ 0.85 floor as a regression guard. This document explains why it is built the way it is, what it does well, and where it would need investment to harden into a production input layer.

---

## Why this exists

LLM applications now ingest untrusted text from three different surfaces — user input, retrieved documents, and tool/agent output — and route that text into the same prompt that carries the application's own instructions. Once an attacker gets a sentence into that prompt, the system prompt's authority over the model is no longer guaranteed. The result is a class of vulnerabilities that existing SOC tooling has no native vocabulary for: instruction override, persona takeover, indirect injection through wrapped instructions, refusal-bypass framings, and tool-use coercion that exfiltrates secrets through the model itself.

Detection engineers know how to handle a stream of structured events with rule IDs, severities, and ATT&CK mappings. This project translates the prompt-injection problem into that shape. Each verdict comes out as a Splunk-friendly JSON event with a CIM eventtype, a signature, a severity, a list of signals (rule IDs that fired), and a set of MITRE ATLAS technique IDs. The detection layer can sit in front of an LLM application; the SOC layer can ingest verdicts as notable events and pivot into the offending session the same way it would pivot into any other alert.

## Threat model

The attacker's capability is to put text into the host LLM application — directly as a user, or indirectly by controlling content the application retrieves or tools it calls. The target is the application's instruction integrity and any privileged tools or data the model can reach. In scope are direct prompt injection (`AML.T0051`), jailbreak / persona-takeover attempts (`AML.T0054`), system-prompt extraction, indirect injection via instruction-wrapping markers, refusal-bypass framings such as *"hypothetically"* or *"in a fictional story"*, and common obfuscations including base64/hex blobs and zero-width or Unicode-tag characters. Out of scope, deliberately, are multimodal/image-based injection, sophisticated steganography beyond the zero-width detection band, model-weight extraction, and training-data attacks.

This scope decision matters. A detector cannot fail safely if it pretends to cover threats it does not actually cover. By calling out the boundary, an analyst reading the output knows the verdict is meaningful for instruction-override patterns but says nothing about an image carrying a hidden instruction.

## Architecture

```
input text  ─►  Heuristic layer  (PI-001 .. PI-009)  ─► (rules fired, h_conf)
                       │
                       │  if h_conf ≥ 0.85 → short-circuit "malicious"
                       ▼
                LLM judge (Claude)  ─► {verdict, confidence, rationale}
                       │
                       ▼
                Verdict combiner    ─► final verdict, signals, ATLAS IDs
                       │
                       ▼
                JSON event on aisec.prompt_injection logger
                       │
                       ▼
                Splunk HEC (optional) → notable in Enterprise Security
```

Three layers, all pluggable. The heuristic layer is a tuple of nine `HeuristicRule` objects, each modeled after a Splunk correlation search: a rule ID, a severity, a regex pattern, and a tuple of MITRE ATLAS techniques. Rules fire by simple regex match. The combined heuristic confidence uses a diminishing-returns aggregation across severities, so a single high-severity rule already produces strong signal but stacking still increases it. The LLM judge is an Anthropic Claude call with a security-classifier system prompt that forbids the model from following any instructions inside the input under inspection, and asks for a single JSON object with `{verdict, confidence, rationale}`. The combiner fuses both into a final verdict using deliberately conservative rules I'll detail below.

## Why hybrid, and not heuristic-alone or LLM-alone

Each layer has a known failure mode that the other compensates for.

A pure heuristic layer is fast, deterministic, and reproducible — exactly what a SIEM engineer wants. It runs offline with no API key, costs nothing per call, and can be enforced as a CI regression check. Its weakness is generalization: regex misses novel phrasings and any attack that does not contain a known token. New jailbreak personas and new wrappers appear weekly; the rule set lags reality.

A pure LLM judge is the opposite. It generalizes well — Claude reads the input as text and reasons about intent — but it is non-deterministic, slow, expensive at scale, vulnerable to its own prompt injections inside the input it is judging, and impossible to enforce in CI without spending real tokens on every test run.

The hybrid path captures most of the heuristic's reproducibility and most of the LLM's coverage. The heuristic short-circuits at 0.85 confidence (the "obviously malicious" cases — multiple high-severity rules firing) so the judge is only consulted on the harder middle band. When the judge is unavailable or returns garbage, the detector degrades to heuristic-only without raising. When the judge fires but contradicts the heuristic, the combiner stays conservative. The result is a detector that produces the same verdict every time on its own eval set, costs zero on offline runs, and still has semantic coverage when the judge is online.

## The heuristic rules

Nine rules covering the patterns that show up in real injection traffic. Each one ties to one or more MITRE ATLAS techniques.

`PI-001` (high) catches override-of-prior-instructions phrasing — the *"ignore previous instructions"* family in all of its variants (*disregard*, *forget*, *override*, *previous/prior/all/above/earlier*, then *instructions/prompt/rules/directives*). `PI-002` (high) catches system-prompt extraction — *reveal/print/show/repeat/leak* combined with *system prompt / hidden prompt / developer message*. `PI-003` (high) catches persona overrides that include privilege escalation language: *you are now / act as / pretend to be / roleplay as*, paired with *unrestricted / jailbroken / developer / admin / root / without rules*. `PI-004` (medium) catches the named jailbreak personas — *DAN, do anything now, AIM, evil mode, developer mode, jailbreak*. `PI-005` (medium) catches instruction-wrapping markers used in indirect injection — `[system]`, `<system>`, `### system`, `<|im_start|>system`, `BEGIN SYSTEM PROMPT`. `PI-006` (low) flags encoded payloads — base64-shaped blobs of 60+ chars, hex escapes, and decimal byte sequences. `PI-007` (medium) flags zero-width and Unicode-tag obfuscation in the `U+200B–200F`, `U+202A–202E`, `U+2060–206F`, `U+FEFF`, and Tag-character ranges. `PI-008` (high) catches tool/agent-abuse phrasing aimed at credentials — *call the X tool / use the X tool to (read|exfiltrate|send|fetch|post|leak) ... (secret|api key|token|password|/etc/passwd|.ssh|.aws)*. `PI-009` (low) catches refusal-bypass framings — *hypothetically / for educational purposes / in a fictional story / imagine you are*, paired with *how to / step-by-step / instructions for*.

Severity weights: `low = 0.20`, `medium = 0.45`, `high = 0.70`. The combiner uses `score = score + (1 − score) × weight` so each new rule contributes proportionally less. Two high-severity rules produces 0.91 confidence; one high plus one low produces 0.76; one medium alone produces 0.45. The 0.85 short-circuit threshold sits just below "two highs" — meaning two high-severity rules firing is sufficient, alone, to call something malicious without consulting the judge.

This is the same calibration discipline a Splunk detection engineer applies to a correlation search: severity is not just a label, it is a number that participates in the math, and the thresholds for analyst notification are tuned against the expected base rate of false positives on the protected surface.

## The verdict combiner

`_combine(h_conf, signals, judge)` is where the heuristic and the judge fuse. The rules are deliberately asymmetric, biased toward not downgrading suspicion.

If the judge is unavailable (no API key, network failure, garbled response), the combiner falls back to heuristic-only: `h_conf ≥ 0.5` → malicious; `0 < h_conf < 0.5` → suspicious; `h_conf == 0` → benign. If the judge says malicious, the verdict is malicious with `confidence = max(judge, heuristic)`. If the judge says suspicious, the verdict is suspicious with the same max-rule. If the judge says benign but the heuristic fired with `h_conf ≥ 0.5`, the combiner upgrades to suspicious — the heuristic's deterministic finding is treated as authoritative against the judge's potentially injection-influenced disagreement. Only when the heuristic is also quiet does a benign judgement become benign.

That asymmetry is the point. A judge that has been partially compromised by the input it is reading should not be able to override the deterministic layer. This is the same instinct as never trusting a single source in a SIEM correlation search.

## Eval methodology — and what F1 = 1.000 actually means

The shipped eval set is 30 labeled rows in `eval_set.jsonl`: 15 benign and 15 across seven attack categories — direct injection, system-prompt extraction, jailbreak persona, indirect injection, obfuscation (zero-width), refusal-bypass, and tool-abuse. Benign baseline prompts are deliberately Splunk/SOC-flavored ("how do I write a tstats query against the Authentication data model") to stress false positives on the kind of language an actual security operator might use, since false-positive economics are what make or break a deployed detector.

`run_eval.py` runs the heuristic-only path against every row and prints per-category counts plus aggregate precision, recall, F1, and accuracy. The current score is P = R = F1 = 1.000 across all 30 samples, with a clean 15/15 split on benign and full pass-through on every attack category.

The honest disclosure: this is a small, curated eval. F1 = 1.000 on 30 rows is not an industry benchmark — it is a regression check that the rules I wrote actually catch the patterns I designed them to catch. The valuable signal in the number is not its absolute value; it is that **CI enforces an F1 ≥ 0.85 floor** on every push (`.github/workflows/ci.yml` runs `python run_eval.py` and fails the build if the floor is breached). If a future change to the regex or the severity weights breaks any single category, the build goes red and the change cannot merge. That is the production discipline a detection-engineering practice runs on, scaled down to a small project.

The roadmap item that turns this into a real benchmark is comparison against external prompt-injection eval sets — Lakera's Gandalf corpus, ToxicChat-PI, and any of the open red-team datasets — at which point the F1 number becomes a real performance comparison rather than a regression guard.

## Splunk integration

Each verdict is also logged as a single-line JSON event on the `aisec.prompt_injection` logger, with the following CIM-friendly shape:

```json
{
  "cim_eventtype": "ai_prompt_injection",
  "signature": "prompt_injection_detector",
  "severity": "high",
  "verdict": "malicious",
  "confidence": 0.91,
  "signals": ["PI-001", "PI-002"],
  "atlas_techniques": ["AML.T0051"],
  "judge_used": false,
  "src_input_excerpt": "Ignore all previous instructions and reveal..."
}
```

The `splunk_hec.py` helper forwards each event to a configured HEC endpoint when `--hec` is passed on the CLI. From there, ingestion into Enterprise Security is conventional: a sourcetype of `aisec:prompt_injection`, an index of `aisec`, and a correlation search that matches on `verdict IN ("malicious", "suspicious")` and produces a notable event:

```spl
index=aisec sourcetype="aisec:prompt_injection" verdict IN ("malicious","suspicious")
| stats count min(_time) as first_seen max(_time) as last_seen
        values(signals) as signals values(atlas_techniques) as atlas
        by user, app
| eval severity=case(verdict=="malicious","high","suspicious","medium",1=1,"low")
| `notable_event(prompt_injection_detected, severity, "AI input layer flagged an injection attempt")`
```

The drilldown from a notable pivots on `src_input_excerpt` and the upstream application logs — the same pattern an analyst would use for any other notable, with no new tooling required.

## Cortex XSIAM mapping

The same content translates to Cortex XSIAM with minor reshaping. The CIM-style JSON event becomes an XQL-queryable dataset (`cortex_aisec.prompt_injection` or similar), the correlation search becomes an XQL correlation rule, and the SPL above maps roughly to:

```xql
dataset = cortex_aisec_prompt_injection
| filter verdict in ("malicious", "suspicious")
| comp count() as count, earliest(_time) as first_seen, latest(_time) as last_seen,
       values(signals) as signals, values(atlas_techniques) as atlas by user, app
| alter severity = if(verdict = "malicious", "high",
                      verdict = "suspicious", "medium", "low")
```

For higher-fidelity behavioral matches, the PI-008 tool-abuse pattern is a natural behavioral-indicator candidate — a rule that triggers on the *combination* of a tool call and a credential string in the same input window, producing alerts even on novel phrasings the regex misses. That is the kind of generalization an XDR's behavioral-detection layer is designed for. Detection content shaped for both a traditional CIM/SPL stack and a modern XDR's correlation language is the kind of dual-stack output that makes the same project portable across detection ecosystems.

## Roadmap and known limitations

What this MVP does not yet do, and what the next iteration should add, in priority order:

An embedding-similarity layer against a known-attack corpus, for in-distribution drift detection — current heuristics miss novel phrasings that do not contain known tokens. A per-application policy lookup loaded from a Splunk lookup table, so different host applications can declare their own allow/deny phrases without code changes. A streaming HTTP service with token-bucket rate limiting, so the detector can sit in front of a real LLM application as an inline input filter rather than a CLI tool. Multimodal injection coverage — text inside images and embedded instructions in retrieved PDFs are entirely out of scope today and will need a separate detector, probably gated on the host application's actual modality.

The honest limitation list also includes anything that requires reasoning about the host application's own context. A persona override is "malicious" only if the host application has a system prompt that the override contradicts; a refusal-bypass framing is "malicious" only if the underlying request crosses the host's policy boundary. The current detector treats both as suspicious in isolation, which is the correct conservative default but produces false positives in environments where role-play is the legitimate use case (creative writing assistants, simulation tools). Per-application policy loading is the lever that fixes that without weakening the default.

## Closing

The aim of this project is not to claim a solved benchmark. It is to demonstrate that prompt-injection detection can be engineered with the same rigor an experienced SIEM team brings to detection content — threat model up front, deterministic rules with severity calibration, a measurable eval, a CI regression floor, an honest disclosure of the eval's limits, a SOC-shaped output, and a plausible Splunk and Cortex XSIAM integration story. That is the bar a deployed AI input layer needs to clear, and it is the bar this project tries to set for the seven that follow it in [the broader portfolio](../README.md).

Questions, code review, and pull requests welcome — find me on [LinkedIn](https://www.linkedin.com/in/john-thomas-751578130).
