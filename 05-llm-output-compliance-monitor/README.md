# 05 — LLM Output Safety & Compliance Monitor

[![CI](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml/badge.svg)](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![FedRAMP-aware](https://img.shields.io/badge/FedRAMP-aware-blue.svg)](https://www.fedramp.gov/)
[![NIST AI RMF](https://img.shields.io/badge/NIST%20AI%20RMF-1.0-blue.svg)](https://www.nist.gov/itl/ai-risk-management-framework)
[![NIST 800-53](https://img.shields.io/badge/NIST%20800--53-AU%20%7C%20SI--12-orange.svg)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
[![NVIDIA NeMo Guardrails](https://img.shields.io/badge/NVIDIA-NeMo%20Guardrails-76B900.svg)](../nemo_guardrails/)

> **A runtime output guardrail that inspects every LLM-generated response
> for PII, secrets, classification-marker spillage, and successful-jailbreak
> markers. Every decision is recorded to a hash-chained, tamper-evident
> audit log — the FedRAMP-flavored integrity-evidence pattern this project
> is built around.** Embeddable as a library; CLI for batch / replay
> evaluation against historical-output corpora.

**Status:** Working MVP. Ships with four output filters, a hash-chained
audit log with tamper-detection, sample good/bad output corpora,
end-to-end pytest coverage including audit-chain integrity verification,
and a CI job that replays the full sample corpus through the monitor and
verifies the audit chain on every push.

## Demo

[![asciicast](https://asciinema.org/a/pJJtRvsZFHWFD8OE.svg)](https://asciinema.org/a/pJJtRvsZFHWFD8OE)

90-second walkthrough — the shipped good/bad corpora, the monitor
replaying both (`0/3/8` on the bad corpus, `8/0/0` on the good corpus),
the hash-chained audit log validation across all entries, and the
chain-binding visible in the audit JSON itself (each entry's `prev_hash`
tying to the previous entry's `hash`). Click the cast above to play,
or run it yourself:

```bash
cd 05-llm-output-compliance-monitor
./demo.sh
```

## Threat model

| | |
|---|---|
| **Attacker capability** | Either (a) an end user attempting to elicit prohibited content from the LLM, or (b) an upstream prompt-injection (Project 1's territory) that has already coerced the model into producing unsafe output. |
| **Target asset** | The downstream consumer (user, application, tool) of the model output — and the integrity of the audit trail that records what the model said. |
| **In scope** | PII leakage (LLM02), secret / credential leakage (LLM02), classification-marker spillage (LLM02 + governance), successful-jailbreak markers in output (LLM01 / LLM09 — output side), audit-trail tamper-evidence. |
| **Out of scope** | Multi-turn conversational state (the monitor scores one response at a time); upstream input detection (Project 1's job); content-safety / harmful-output classification using an LLM judge (planned roadmap — current MVP is regex-deterministic for CI reproducibility). |

## Architecture

```
                        LLM-generated response
                                  │
                                  ▼
            ┌──────────────────────────────────────┐
            │         OutputMonitor                │
            │                                      │
            │   ┌────────────┐ ┌────────────────┐  │
            │   │ PIIFilter  │ │ SecretsFilter  │  │
            │   │ (REDACT)   │ │ (BLOCK)        │  │
            │   ├────────────┤ ├────────────────┤  │
            │   │ Classifi-  │ │ PolicyFilter   │  │
            │   │ cation     │ │ (jailbreak     │  │
            │   │ Filter     │ │  ack markers)  │  │
            │   │ (BLOCK)    │ │ (BLOCK)        │  │
            │   └────────────┘ └────────────────┘  │
            │                                      │
            │   verdict = max(action, precedence)  │
            │   pass | redact | block              │
            └────────────────┬─────────────────────┘
                             │
                             ▼
            ┌──────────────────────────────────────┐
            │   HashChainAuditLog (JSONL)          │
            │                                      │
            │   entry_n.prev_hash = entry_(n-1).hash│
            │   entry_n.hash      = sha256(...)    │
            │                                      │
            │   verify_chain() — tamper detection  │
            └──────────────────────────────────────┘
                             │
                             ▼
                    Decision returned
                    to the caller:
                    pass / redact / block
```

Library + CLI. The `OutputMonitor` is embeddable in any LLM application.
The CLI replays JSONL corpora of historical outputs through the monitor
for compliance backfill — useful when you've added a new filter and need
to scan everything the model said in the past 90 days against the new
rule.

## The four filters

**`PIIFilter` — REDACT action.** Catches emails, US SSNs, US phone numbers,
and Luhn-validated credit-card numbers. Each match becomes a redaction
finding with a category-labeled placeholder (`[REDACTED:EMAIL]`,
`[REDACTED:SSN]`, etc.) so the analyst-visible response acknowledges what
was removed without leaking the original. Maps to LLM02 / `AML.T0024` /
`MEASURE 2.10`.

**`SecretsFilter` — BLOCK action.** Catches AWS access keys, GitHub
tokens, Slack tokens, Anthropic / OpenAI API keys, and PEM-block private
keys. Block (not redact) is the right action — even acknowledging that a
redacted secret existed in the response is information disclosure. The
host application surfaces a generic refusal to the user. Maps to LLM02 /
`AML.T0024` / `MEASURE 2.10`.

**`ClassificationFilter` — BLOCK action.** Catches CUI, FOUO,
CONFIDENTIAL, SECRET / TOP SECRET, ITAR / Export-controlled,
ATTORNEY-CLIENT PRIVILEGED, and PHI / HIPAA markers in LLM output. A
model producing classification markers is one of: reproducing a
classified source it shouldn't have access to, hallucinating a marker
(still a policy violation in audited environments), or replaying a
system-prompt that itself contained the marker. In any case, block —
the upstream pipeline failed and security needs to know. Maps to LLM02 /
`GOVERN 1.3`.

**`PolicyFilter` — BLOCK action.** The output-side counterpart to
Project 1's input-side detector. Catches markers of *successful*
jailbreaks: `as DAN`, `developer mode is on`, `I have no restrictions`,
`override accepted`, etc. If the response contains these phrasings, the
model was successfully jailbroken — the conversation is compromised and
must be reset. Maps to LLM01 / `AML.T0054` / `MEASURE 2.6`.

## The hash-chained audit log — the FedRAMP differentiator

Every decision the monitor makes — pass, redact, or block — is appended
to a JSONL audit log. Each entry's hash is bound to the previous entry's
hash:

```
entry_n.prev_hash = entry_(n-1).hash
entry_n.hash      = SHA256(entry_id || timestamp || verdict ||
                            findings || excerpts || prev_hash)
```

**Tamper detection.** If anyone modifies a past entry — changes a verdict
from `block` to `pass`, deletes a finding, edits an excerpt — the
recomputed hash no longer matches the stored hash, and `verify_chain()`
flags the offending entry's index. Inserting a synthetic entry between
two real ones produces the same effect: the inserted entry's `prev_hash`
won't match the real previous entry's hash.

This is the integrity-evidence pattern federal compliance audits expect.
Same family as S3 Object Lock, blockchain-style immutable-log systems,
Splunk's signed audit log, AWS CloudTrail integrity validation. The
project implements it directly so compliance integrity is a property of
the artifact itself — not of whatever storage system happens to be
underneath. That portability matters for FedRAMP evaluations where the
auditor wants to reason about the audit trail without trusting the
storage layer.

## Quick start

```bash
cd 05-llm-output-compliance-monitor
pip install -r requirements.txt

# Replay the bad-output corpus through the monitor
python3 monitor.py --corpus samples/bad_outputs.jsonl --audit-log out/audit.jsonl
# Expected: 0 pass · 3 redact · 8 block, audit-log written to out/audit.jsonl

# Replay the good-output corpus — every response should pass
python3 monitor.py --corpus samples/good_outputs.jsonl --audit-log out/audit.jsonl
# Expected: 8 pass · 0 redact · 0 block

# Verify the hash chain
python3 monitor.py --verify out/audit.jsonl
# Expected: "Audit chain valid — N entries verified."

# Tests (offline)
pytest -q
```

## Library use

```python
from monitor import OutputMonitor

mon = OutputMonitor(audit_log_path="audit.jsonl")
decision = mon.check(llm_response_text)

if decision.blocked:
    return generic_refusal_to_user()
return decision.response_out   # may be redacted; safe to return
```

## NVIDIA NeMo Guardrails (optional fifth filter)

Pass `include_nemo_guardrails=True` to append the
[`NeMoGuardrailsFilter`](./filters/nemo_guardrails_filter.py) to the
default chain. The new filter delegates to the portfolio's NeMo
Guardrails app at [`../nemo_guardrails/`](../nemo_guardrails/) — same
secret / classification / jailbreak detection vocabulary, expressed as
programmable Colang output rails:

```python
mon = OutputMonitor(
    audit_log_path="audit.jsonl",
    include_nemo_guardrails=True,
)
# mon.filters now has 5 filters; the 5th is the NeMo Guardrails layer.
decision = mon.check(llm_response_text)
# Findings from the new filter carry filter_name="nemo_guardrails"
# and BLOCK action. They flow into the same hash-chained audit log.
```

Default is OFF, so existing CI corpus replay assertions and audit-log
shape are unchanged. When enabled:

- The new filter fires on the same secret / classification /
  jailbreak vocabulary the four core filters detect (deliberate
  redundancy — demonstrates layered defense-in-depth).
- Findings carry `filter_name="nemo_guardrails"`, `action=BLOCK`, and
  the appropriate OWASP / MITRE ATLAS / NIST AI RMF tags.
- Decisions flow into the existing hash-chained audit log; chain
  integrity is preserved across mixed runs.
- The integration is fail-open: if the action layer can't be
  imported, the new filter returns no findings and the four core
  filters proceed unaffected.

The library never raises — filters catch their own exceptions, the
monitor returns a `pass` for any response that produced no findings, and
the audit log appends atomically. Intended for embedding in production
LLM applications where the monitor cannot be a source of latency spikes
or unhandled exceptions.

## Output

`out/audit.jsonl` — one entry per decision, append-only. Each entry
includes the entry ID, ISO timestamp, decision verdict, finding
summaries (with secret / classification matches redacted in the audit
log itself — even the audit shouldn't carry the leaked value), excerpts
of the original and post-redaction responses, the previous entry's hash,
and the current entry's hash.

Verification is a single command:

```bash
python3 monitor.py --verify out/audit.jsonl
```

Returns exit code 0 + `Audit chain valid — N entries verified.` if the
chain is intact, or exit code 2 + `Audit chain BROKEN at entry index K`
with the failure reason if any past entry has been tampered with.

## Splunk / SOC tie-in

Every audit entry is shaped for direct ingestion to Splunk via HEC. A
scheduled `tail` of the audit log into HEC, plus a Splunk ES correlation
search in Project 4's content pack, yields:

```spl
index=aisec sourcetype="aisec:output_compliance" decision_verdict="block"
| stats count values(findings{}.category) as categories by app
| `notable_event(output_blocked, "high", "Compliance monitor blocked an LLM response")`
```

Spike-on-block-rate alerting is the most operationally useful pattern —
a sudden cluster of blocks usually indicates either an injection campaign
underway against the host application or a model regression that started
producing unsafe content.

## What's not in MVP (roadmap)

- **AWS Lambda + API Gateway deployment.** A Terraform module under
  `infra/` for FedRAMP-aware deployment to AWS GovCloud — Lambda
  function, API Gateway endpoint, S3 bucket with Object Lock for
  WORM audit storage, KMS CMK with customer-managed keys.
- **Splunk HEC streaming for audit log.** Currently the audit log is a
  local JSONL file. Production deployment would tail the file into HEC
  in near-real-time alongside the local copy.
- **Claude judge for ambiguous cases.** A fifth filter that uses Claude
  to score harmful-content categories (violence, hate speech,
  self-harm) the regex layer can't catch with high precision.
- **Semantic similarity for paraphrased jailbreak markers.** A scanner
  that flags responses whose embeddings fall close to a known-jailbreak-
  acknowledgement corpus, catching paraphrases the regex layer misses.
- **Per-application policy.** YAML-loaded policy that lets different
  host applications declare their own allow/deny content categories
  (medical applications need PHI handling; legal applications need
  attorney-client allowance; etc.).

## Compliance mapping

NIST 800-53 controls this project provides evidence for:

- **AC-4 Information Flow Enforcement** — content classification gates
  the egress of LLM output.
- **AU-2 Audit Events** — every monitor decision is auditable.
- **AU-9 Protection of Audit Information** — hash-chained log resists
  tampering by privileged users.
- **SI-12 Information Output Filtering** — direct mapping; this project
  is the SI-12 control for an AI workload.
- **SI-15 Information Output Filtering for Privileged Functions** —
  PolicyFilter blocks when the model has effectively self-elevated.

NIST AI RMF 1.0:

- **MEASURE 2.6** — content harms measured.
- **MEASURE 2.10** — privacy risk measured.
- **MANAGE 2.3** — risks of AI tool / agent misuse managed at output
  layer.
- **GOVERN 1.3** — policies for restricted-marker handling enforced.

## Why this matters for the portfolio

Project 1 catches injection at the LLM input layer. This project catches
the cases where Project 1 missed and the model produced unsafe output
anyway — a defense-in-depth pair. Project 3 catches threats at corpus
ingestion before retrieval. Together with the red-team framework
(Project 2) and the SIEM correlation generator (Project 4), this is now
*five* working MVPs that share an event vocabulary, a taxonomy, and a
Splunk integration story.

The hash-chained audit log specifically addresses the integrity-evidence
gap most AI-security tooling has. Most output filters log to a regular
file or a database where a privileged user can edit history without
detection. Federal compliance evaluations will not accept that. By
implementing the integrity binding directly in the audit-write path, the
log's tamper-evidence is portable across deployments — the same
guarantee holds whether the log lives on local disk, in S3 with Object
Lock, in a Splunk index, or all three at once. That is the
detection-engineering-meets-federal-compliance pattern this portfolio is
built to demonstrate.
