# RAG Pipeline Security Auditor — Engineering Write-up

**Project:** [03 — RAG Pipeline Security Auditor](./README.md)
**Author:** [John Thomas](https://www.linkedin.com/in/john-thomas-751578130) — Principal Splunk Consultant; 9+ years federal SIEM and detection engineering.
**Repo:** [github.com/johnlorenthomas14/ai-security-portfolio](https://github.com/johnlorenthomas14/ai-security-portfolio)

> A static corpus scanner that finds indirect-injection payloads, PII,
> credentials, and sensitivity-marker leaks in retrieval-augmented-generation
> corpora *before* documents enter the retrieval index. Reuses
> [Project 1](../01-prompt-injection-pipeline/README.md)'s prompt-injection
> detector as one of four scanner classes; produces Splunk-ingestible
> JSON findings and an analyst-readable Markdown audit keyed by NIST AI
> RMF subcategory. This document explains why the auditor takes a
> static-corpus shape rather than a live-RAG-probe shape, why the four
> scanner classes were chosen, where the design draws explicit
> false-positive trade-offs, and how the same artifact serves both SOC
> and GRC audiences.

---

## Why this exists — and why static, not live

A modern Retrieval-Augmented Generation (RAG) system has three failure
surfaces that don't exist in a non-RAG LLM application:

1. **The corpus itself.** Anything in the corpus can end up in a prompt.
   If the corpus contains injection payloads, they hijack the LLM at
   retrieval time. If it contains PII, the LLM may reproduce that PII
   in user-visible answers. If it contains classified or controlled
   content, an LLM that's allowed to retrieve from it bypasses the
   document-level access controls that would normally protect that content.
2. **The retrieval layer.** Vector similarity, keyword search, hybrid
   ranking — each has its own failure modes around relevance and
   inclusion. But that's downstream of the corpus problem.
3. **The generation layer.** The LLM writing the response. This is
   where Project 1's runtime detector lives.

This project addresses surface (1). Project 1 addresses surface (3).
Project 2 produces the attack corpus that exercises both. Together they
form a defense-in-depth chain, with each project covering a different
*phase* of the same RAG security problem.

The choice to scan the corpus *statically* — at ingestion time, not at
retrieval time — is deliberate and worth justifying explicitly, because
several other RAG security tools take the live-probing path instead.

**Static corpus scanning is the right shape for the input-side problem.**
The corpus is the source of truth for what the retrieval layer can
return. If a document with an injection payload makes it into the
corpus, every subsequent retrieval that includes that document carries
the payload — and *every* RAG retrieval is non-deterministic, so you
cannot observe at runtime whether you've been compromised. Catching
the document at ingestion is the only point in the pipeline where you
can guarantee the issue doesn't propagate.

**Live-RAG probing solves a different problem.** Probing a deployed RAG
system with adversarial queries — the way Project 2 probes a deployed
LLM application — tests whether the *current corpus* + *current
retrieval policy* + *current generation prompt* can be manipulated. It
catches issues this auditor misses (retrieval-layer flaws, ranking
problems, system-prompt weaknesses). But it doesn't tell you whether a
specific document in the corpus is malicious; it only tells you whether
your output is malicious. The two approaches are complementary, not
substitutes. Building both — live probing in Project 2's shape *and*
static scanning in Project 3's shape — gives the defense-in-depth
coverage neither alone provides. This project is the static-shape half
of that pair.

## Threat model

The attacker can write into the corpus. That capability looks like one
of several real-world primitives:

| Source | Example |
|---|---|
| Internal wiki | A malicious employee or compromised account edits a Confluence page that's indexed by the corporate-RAG copilot. |
| Support knowledge base | A customer-success agent pastes a customer email verbatim into a knowledge article; the email contains PII that the article inherits. |
| Shared drive | An engineering team puts a `.env` file in a shared OneDrive that's indexed by the company's RAG. |
| Third-party feed | A vendor publishes a documentation update to a public site that the RAG ingests; a competitor or attacker has injected payload text into the vendor's content. |
| Public web crawl | The RAG includes a web-crawled page; an attacker controls a website the crawler visits. |

The attacker does not need code execution, does not need credentials to
the LLM application, does not need to be a user. They need write access
to *anything the indexer reads from*. That surface is dramatically
larger than most teams account for.

The defender's lever is corpus-time scanning. Every document the
indexer would ingest is first run through this auditor. Findings above
a configurable severity gate the document — block the ingest, quarantine
for review, redact-and-allow, or alert the corpus owner. The auditor
does not need to be the policy engine; it needs to produce findings
that a policy engine acts on. That's why the output is two formats:
JSON for programmatic gating, Markdown for human review.

## Architecture — four scanners, one protocol

The architecture is intentionally flat: a `DocumentScanner` protocol
that any scanner implements with a single method, `scan(document) ->
list[Finding]`. The auditor walks the corpus, instantiates four
scanners, and runs each over each document. Findings flow into the
report writer.

The flatness is the right design choice for two reasons. First, it
makes adding a new scanner a single-file operation — drop a new class
into `scanners/`, add it to the auditor's instantiation list, done.
Second, it makes each scanner unit-testable in isolation; the test
suite has one test per scanner against one known-bad demo document,
which gives full coverage without combinatorial explosion.

The four scanner classes were chosen by sweeping the OWASP LLM Top 10
and asking *"which of these can manifest in a corpus document at
ingestion time, and which require runtime probing?"*

| OWASP LLM 2025 | Manifests in corpus? | This auditor |
|---|---|---|
| LLM01 Prompt Injection | Yes (indirect) | `IndirectInjectionScanner` |
| LLM02 Sensitive Info Disclosure | Yes (PII, secrets) | `PIIScanner` + `SecretsScanner` |
| LLM03 Supply Chain | No (training-time) | Out of scope (Project 6) |
| LLM04 Data and Model Poisoning | No (training-time) | Out of scope |
| LLM05 Improper Output Handling | No (host-app concern) | Out of scope |
| LLM06 Excessive Agency | Partial — corpus can grant unsafe-tool guidance | Captured as injection |
| LLM07 System Prompt Leakage | Yes (planted instructions) | Captured by injection scanner |
| LLM08 Vector Weaknesses | No (retrieval-layer) | Out of scope (live-probe shape) |
| LLM09 Misinformation | Yes (poisoned content) | Partial — `IndirectInjectionScanner` catches the jailbreak shape; full content-truth audit is roadmap |
| LLM10 Unbounded Consumption | No (DoS shape) | Out of scope |

That maps directly to the four scanner classes, plus
`SensitivityScanner` which doesn't fit OWASP cleanly but is essential
in any federal or enterprise corpus — classification-marker spillage
is its own threat class.

## The four scanners — what each is, what each isn't

### IndirectInjectionScanner

Reuses Project 1's `PromptInjectionDetector`. Each non-empty paragraph
of each document is run through the detector in heuristic-only mode
(`DetectorConfig(use_llm_judge=False)`), and any paragraph that returns
`suspicious` or `malicious` becomes a finding tagged with LLM01 /
`AML.T0051` / `MEASURE 2.7`.

Two design choices in this scanner deserve commentary.

**Paragraph-level scanning, not whole-document scanning.** A 50-page PDF
with one injection payload should produce one finding pointing at the
payload's paragraph, not 50 noisy findings. Paragraph-level granularity
lets the analyst pivot directly to the offending text via the line
number in the report.

**Heuristic-only by default.** Project 1's detector can use an LLM
judge for ambiguous inputs, but the auditor explicitly disables that.
Reasoning: a corpus may contain thousands of documents and tens of
thousands of paragraphs; running an LLM judge on every paragraph is
prohibitively expensive, and the heuristic layer's deterministic regex
rules already provide high-fidelity coverage of the common
injection-shaped phrasings that appear in real corpus content. The
judge is the right tool for runtime input scoring (where one user
query is one judge call) but the wrong tool for batch corpus scanning.

This is the closing-the-loop piece of the portfolio: a scanner that
runs against the corpus *uses the same regex rule set* the detector
runs against runtime user input. If you tighten one rule, both layers
improve. If you find a false positive, fixing it once fixes both.

### PIIScanner

Deterministic regex for emails, US Social Security Numbers, US phone
numbers, and Luhn-validated credit-card numbers. Tagged LLM02 /
`AML.T0024` / `MEASURE 2.10`.

The deliberate scope cut is name and address detection. Both require
an NER (Named Entity Recognition) model — spaCy, Microsoft Presidio, or
similar. NER on a corpus is achievable but expensive, and NER-shaped
findings carry significant false-positive risk because every plausible
proper noun in a document gets a low-confidence "could be a person's
name" score. Names appear in documents legitimately *all the time*:
authorship attributions, case studies, customer testimonials,
historical references. False-positive cost in a corpus-ingestion gate
is real — every false positive blocks a real document from being
indexed and burns reviewer time on triage.

Regex on structured PII has the inverse trade-off: high precision, low
recall. A 9-digit SSN-shaped string is almost always either an SSN or
a coincidence; the false-positive rate is low. An email is unambiguous.
A Luhn-valid 16-digit string is, with overwhelming probability, a real
credit card. The regex MVP catches the high-precision findings; the
NER layer is a clean roadmap addition for teams that have the
false-positive-budget to spend.

### SecretsScanner

Credentials and API keys in document content. The scanner covers the
patterns that are most often leaked into corporate corpora through
honest mistake — developer notes pasted into a wiki, .env contents
embedded in a runbook, a CI debug log captured in a knowledge article.

The pattern set:

- AWS access key IDs (AKIA, ASIA, AROA, AIDA prefixes)
- GitHub personal access tokens (modern prefixed formats — ghp_, ghu_, etc.)
- Slack tokens (xoxa-, xoxb-, etc.)
- Anthropic API keys (sk-ant- prefix)
- OpenAI API keys (sk- prefix)
- PEM-block private keys (RSA, EC, DSA, OpenSSH)
- Environment-variable assignments naming common credential variables

Every finding from this scanner has its excerpt redacted before being
written to the audit report — the actual leaked secret value is replaced
with `[REDACTED]`. This is essential: the audit itself becomes a
secondary leak vector if the report cleartexts the credential. The
finding's existence and location are sufficient signal; the value
itself is unnecessary for triage.

The PEM-block private key is the most critical finding class in the
scanner. A PEM block in a corpus document is almost always one of two
scenarios — a developer pasted a real key by mistake, or a "fake key
for documentation purposes" that an attacker can still potentially use
against test infrastructure. Either case warrants immediate corpus
removal and key rotation.

### SensitivityScanner

Classification and handling-marker detection. The patterns:

| Marker | Severity | Why |
|---|---|---|
| TOP SECRET | critical | Spillage incident |
| SECRET | critical | Spillage incident |
| CUI | high | 32 CFR 2002 handling required |
| FOUO | high | Pre-CUI legacy marker |
| CONFIDENTIAL | high | Restricted distribution |
| ITAR / Export-controlled | high | Nationality-of-recipient restrictions |
| ATTORNEY-CLIENT PRIVILEGED | high | Privilege waiver risk |
| PHI / HIPAA | high | 45 CFR 164 access control required |
| PROPRIETARY / TRADE SECRET | medium | Contractual NDA risk |

A document carrying any of these markers in a queryable RAG corpus
generally constitutes a policy violation, and at the higher tiers, a
spillage or compliance incident.

The scanner emits at most one finding per marker-kind per document. A
CUI document with the CUI banner repeated on every page produces one
CUI finding, not fifty. This is the correct default for a corpus-scan
output where each finding triggers human review — fifty findings on
the same document is fifty review items, not one.

There is one false-positive edge case worth flagging explicitly: the
word *secret* appears legitimately in environment variable names
(`AWS_SECRET_ACCESS_KEY`), property keys (`secretKey`), and ordinary
prose (*"the secret to good documentation is..."*). The current regex
uses `\bSECRET\b` with `(?<!UN)` lookbehind to suppress *unsecret* /
*unsecretly*. Word boundaries (`\b`) prevent matching SECRET inside
underscore-joined words like `AWS_SECRET_ACCESS_KEY` because underscore
is a word character. This is the right calibration — the false-positive
rate stays manageable for the typical corpus.

## Output design — JSON + Markdown, every run

Every audit produces both `findings.json` and `audit_report.md` in the
output directory. There is no flag to disable either; both are produced
unconditionally because each serves an irreplaceable audience.

`findings.json` is the SOC and pipeline artifact. CIM-shaped fields
(`cim_eventtype="ai_rag_finding"`, `signature`, `event_severity`,
`event_time`) make each finding a Splunk-native event ready for HEC
ingestion. A scheduled audit becomes a recurring scan in Enterprise
Security; an ES correlation search alerts on any new critical or high
finding within the index. Cortex XSIAM mapping is the same shape with
XQL substituted for SPL.

`audit_report.md` is the GRC and human-review artifact. Severity
rollup at the top so a reviewer knows in five seconds whether the audit
needs immediate action. Executive summary that calls out the *action
required* — *"block ingestion; rotate credentials; remove documents"*
for criticals, *"quarantine documents pending review"* for highs.
Findings tabulated four ways (by category, by document, by OWASP
category, by AI RMF subcategory) so different reviewers can pivot on
the dimension they care about. Per-finding details with attack text
excerpts, line numbers, and rationale.

The dual-format output reflects the same insight that Project 2 made
explicit: an AI-security finding has two legitimate audiences, and
producing both formats every run is cheaper than asking either audience
to consume the wrong one.

## Calibration — what the demo corpus proves and what it doesn't

The shipped demo corpus has six documents, four of which are
deliberately polluted to hit specific scanner classes:

- `01-company-handbook.md` — clean except one email address (the
  `support@acme.example.com` line).
- `02-poisoned-faq.md` — a normal-looking FAQ with an indirect-injection
  payload embedded in one section. Tests the injection scanner.
- `03-customer-feedback.md` — verbatim "customer feedback" containing
  emails, phone numbers, an SSN, and a Luhn-valid credit card. Tests
  the PII scanner.
- `04-dev-runbook.md` — staging-environment documentation containing
  AWS keys, a GitHub token, an Anthropic key, a PEM-block private key,
  and several .env-style credential lines. Tests the secrets scanner.
- `05-cui-program-notes.md` — a federal-engagement document marked
  CUI per 32 CFR 2002. Tests the sensitivity scanner.
- `06-product-spec.md` — a clean product-specification document. Tests
  the false-positive floor — should produce zero findings.

When the auditor runs against this corpus, the expected outcome is
roughly fifteen to twenty findings spread across the four scanner
classes, with at least one critical (the PEM block), several high
(credentials, SSN, credit card, CUI marker, indirect-injection), and
several medium-low (emails, phone numbers, sensitivity-marker tail).

The pytest test `test_end_to_end_audit_on_demo_corpus` enforces a
minimum-finding floor and at least one critical, so any change to the
scanners or the corpus that breaks reliable detection fails the build.
A separate test `test_clean_documents_produce_no_findings` runs every
scanner against `06-product-spec.md` and asserts zero findings — the
false-positive regression guard.

What the demo corpus does *not* prove is that the scanners detect every
real-world variant of every threat class. That would require running
the auditor against published red-team corpora (HuggingFace's
prompt-injection datasets, public PII-leak corpora, etc.), which is the
highest-priority roadmap item. The demo corpus is the calibration
floor; cross-corpus benchmarking is the operational signal.

## Splunk integration — same shape as Projects 1 and 2

The integration story is consistent with the rest of the portfolio: HEC
is the idiomatic ingestion path for scheduled-emit-events. A scheduled
auditor run (cron, GitHub Actions, AWS Lambda, Cribl-edge container)
POSTs the findings.json contents to a HEC endpoint. The CIM fields
mean no parsing logic needed at the indexer; events land ready for ES
correlation.

```spl
index=aisec sourcetype="aisec:rag_audit" cim_eventtype="ai_rag_finding" severity IN ("critical","high")
| stats count values(category) as categories values(scanner) as scanners
        by document_path
| `notable_event(rag_corpus_finding, "high", "RAG corpus contains restricted content")`
```

Production hardening levers are identical to those documented in
Project 2: batch the HEC POST, enable HEC ack mode for delivery
guarantees, and drop low-severity findings at the Cribl edge if license
or SVC consumption is the binding constraint. The same architecture
pattern, applied to a different event-emission shape.

The interesting cross-platform observation: the *scanner library* is
SIEM-agnostic. The scanners themselves don't know about Splunk. The
adaptation to Cortex XSIAM is a one-file `report_xsiam.py` parallel to
`report.py`, emitting XQL-shaped events instead of CIM SPL. Detection
content authored once, shippable to two SIEM stacks.

## What's deliberately not in MVP

**Binary document parsing.** PDFs, DOCX, and PPTX make up most real
corpora. The MVP scans text-only formats. Adding `pypdf`,
`python-docx`, and `python-pptx` is a one-file extension to the
auditor's recognized-extension list, but each binary format introduces
its own text-extraction quirks (OCR for scanned PDFs, tracked changes
in DOCX, speaker notes in PPTX) that need handling. Roadmap.

**NER-shaped PII.** Names, addresses, identifiable references that
require a model rather than a pattern. The roadmap target is Microsoft
Presidio, which has a clean federal-friendly pedigree and supports
custom recognizers for federal-specific identifiers (DoD ID numbers,
common government doc types).

**Embedding-similarity scan.** A scanner that flags documents whose
embeddings fall close to known-attack-corpus vectors. Useful for
catching novel injection phrasings that the regex layer misses. The
right architecture is a sidecar Faiss or Chroma index loaded from a
known-attack corpus (Lakera Gandalf, ToxicChat-PI, etc.) with a
similarity threshold per finding.

**Per-document risk score.** Aggregate findings for one document into a
single risk score and an ingest / quarantine / block recommendation.
This is the policy-engine layer the auditor currently expects an
external system to provide; bringing it inside the auditor would let
the same tool run as a corpus-ingestion gate without external scripting.

**Live RAG-system audit.** A separate project — probe a running RAG
endpoint with adversarial queries the way Project 2 probes a running
LLM. Different shape (live target, latency budget, conversation state),
different architecture, complementary to this static-corpus work.

## Why this matters for the portfolio

Project 1 detects injection at the LLM input layer at runtime. Project
2 probes deployed LLM applications for vulnerability classes. Project 3
shifts left — auditing the corpus before any of those runtime issues
have a chance to manifest. The three projects together form the full
defense-in-depth chain across RAG security: pre-ingestion scanning (P3),
runtime input inspection (P1), and continuous adversarial validation (P2).

Each project produces output in the same shape (CIM-aligned JSON +
AI-RMF-aligned Markdown). Each project tags findings with the same
taxonomies (OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF). Each project's
output flows into the same Splunk ingestion pipeline. The compounding
isn't accidental; it's the design intent.

The federal-compliance angle is what makes this triplet practically
useful in regulated environments. NIST AI RMF 1.0 organizes AI risk
management into Govern / Map / Measure / Manage functions. Each
function needs evidence — *what controls are in place, what risks
have been measured, what actions have been taken*. The three projects
together produce continuous-monitoring evidence across all four
functions:

- **Govern** — sensitivity-marker scanning enforces classification
  policy at corpus boundaries (Project 3).
- **Map** — the threat models in each project's README identify
  contextual AI risks per the framework's expectation.
- **Measure** — every project produces measurable findings tagged with
  AI RMF subcategories. Continuous-monitoring evidence in JSON form.
- **Manage** — runtime detection (Project 1), corpus controls (Project
  3), and adversarial validation (Project 2) are the management
  controls themselves.

That is the AI-governance posture federal customers need and very few
off-the-shelf RAG products provide today. Building it as a portfolio
project rather than a product is not the limitation it sounds like —
the architecture is reproducible, the code is portable, and the same
patterns apply to any team that wants to bring AI workloads into a
FedRAMP-aligned compliance program.

---

Questions, code review, and pull requests welcome — find me on
[LinkedIn](https://www.linkedin.com/in/john-thomas-751578130).
