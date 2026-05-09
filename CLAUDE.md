# CLAUDE.md — AI Security Portfolio

This file is loaded automatically each session. It exists so Claude can pick up
context about who is building this portfolio and how to work in it without
re-asking.

---

## About the author

- **Name:** John Thomas
- **Location:** Fairfax, VA
- **Email:** johnlorenthomas@gmail.com  •  **LinkedIn:** linkedin.com/in/john-thomas-751578130
- **Current role:** Principal Technical Splunk Consultant / Principal Splunk Engineer at **Qmulos LLC** (Jul 2020 – present)
- **Prior role:** Cybersecurity Analyst (Splunk) at Mission First Solutions (Dec 2016 – Jul 2020)
- **Experience:** 9+ years building, operating, and tuning Splunk-based
  SIEMs in federal and Fortune-500 environments — IRS, federal public
  health, federal oversight, federal health, large global financial-services
  firm, enterprise banking. Deep on Splunk Enterprise, Splunk Cloud
  (FedRAMP), ES, ITSI, SOAR, UBA, CIM TAs, Cribl Stream/Edge, tstats /
  data-model acceleration, detection content tied to NIST 800-53.
- **Compliance / GRC:** Hands-on Qmulos Q-Compliance and Q-Audit deployments
  for federal customers — automated evidence collection and continuous
  compliance against NIST 800-53 / NIST RMF / FedRAMP / CMMC. Project 8
  extends this into AI governance (NIST AI RMF).
- **ML detection (production):** Integrated **Splunk Machine Learning Toolkit
  (MLTK)** with Qmulos Q-Audit dashboards to train and operationalize models
  for anomalous-activity and security detection. This is the production
  analog of the hybrid heuristic / ML detection patterns repeated across the
  portfolio — translates directly into modern XDR / AI-native SIEM platforms.
  Reference it before the portfolio in cover letters and recruiter outreach.
- **Certifications:** ISACA **CISM**; CompTIA Security+; Splunk Core
  Certified Consultant; Splunk Enterprise Certified Architect; Splunk SOAR
  Certified Automation Developer; ES, ITSI, SOAR, UBA, Cloud Migrations
  accreditations; Qmulos Q-Compliance / Q-Audit (deployment + end user);
  Cribl Stream + Edge Admin.
- **Education:** B.S. Economics, George Mason University; A.A.S. Business
  Admin, Northern Virginia Community College.
- **Target role:** AI Security Engineer at a modern XDR / AI-native SIEM
  vendor or cleared/federal-experienced security shop. Specific company
  targets are tracked in the gitignored strategy doc, not here.
- **Why this portfolio:** Translate proven detection-engineering, SOC-tooling,
  and federal-compliance skills into the AI/LLM security domain. Each project
  should produce something an AI Security Engineer hiring manager can read in
  five minutes and a security engineer can run in five more.

## The 9 projects (status: all working MVPs as of the build sprint completion)

1. **LLM Prompt Injection Detection Pipeline** — hybrid heuristic + Claude-judge
   detector at the LLM input layer; F1=1.000 on shipped eval, CI floor enforced;
   ATLAS-tagged verdicts forwarded to Splunk ES as notables.
2. **AI Red-Team Automation Framework** — 20 OWASP LLM Top 10 probes against
   any LLM target; three-layer scorer reuses Project 1; AI-RMF-aligned
   evidence report.
3. **RAG Pipeline Security Auditor** — static corpus scanner with four
   classes (indirect-injection, PII, credentials, sensitivity markers).
4. **SIEM Correlation Rule Generator for AI Workloads** — one canonical YAML
   rule → four platform-native outputs (Splunk ES, Sigma, Cortex XSIAM XQL,
   NVIDIA Morpheus pipeline configs).
5. **LLM Output Safety & Compliance Monitor** — runtime output guardrail
   with hash-chained tamper-evident audit log (FedRAMP-flavored integrity).
6. **AI Model Supply Chain Risk Scanner** — pickle-opcode disassembly without
   execution + provenance + risky-deps; CycloneDX 1.5 SBOM fragment output.
7. **Adaptive Threat Intelligence Summarizer** — STIX 2.1 → cited briefs +
   Splunk notables; citation verifier rejects hallucinated references.
8. **NIST AI RMF Compliance Gap Analyzer** — capstone; reads Projects 1-7's
   outputs and produces continuous-monitoring evidence + gap report.
9. **Autonomous SOC Analyst Agent** — agentic tool-use loop with six analyst
   tools, defended at the input layer by Project 1; 8-case eval suite at
   100% pass rate; CI-gated at 75% pass-rate floor.

## Portfolio thesis (use to break ties on design choices)

When making design choices, prefer the option that:

1. **Looks like detection engineering, not a demo.** Each project should
   have inputs, a detector/eval/guardrail, and measurable output (precision,
   recall, F1, or a clear pass/fail signal).
2. **Has a Splunk/SOC tie-in where natural.** Splunk HEC forwarding,
   CIM-aligned field naming, notable event mapping, savable as a
   correlation search. State the tie-in even if it's a stub.
3. **Speaks federal/compliance fluently.** NIST 800-53, NIST AI RMF
   (AI 100-1), FedRAMP, FISMA, MITRE ATT&CK + MITRE ATLAS. Cite control
   IDs in READMEs.
4. **Is reproducible offline.** Heuristic / deterministic paths must run
   without an API key so reviewers can clone and `pytest` immediately.
5. **Documents the threat model.** Every README has a Threat Model section:
   attacker capability, target asset, in-scope vs. out-of-scope.

## Tech stack & conventions

- **Language:** Python 3.11+
- **LLM SDK:** `anthropic` (official Anthropic Python SDK)
- **Default model:** `claude-sonnet-4-5` for judges/agents,
  `claude-haiku-4-5` for high-throughput classification. Always read the
  model from `CLAUDE_MODEL` env var with a sane default — never hardcode.
- **Auth:** `ANTHROPIC_API_KEY` from environment. Never commit keys; every
  project ships a `.env.example`.
- **Testing:** `pytest`. Tests must run with no network and no API key
  (mock the SDK or skip cleanly).
- **Style:** Type hints on public functions. Docstrings explain the threat
  model, not the syntax.
- **Detector output schema:** dict with
  - `verdict` ∈ `benign | suspicious | malicious`
  - `confidence` ∈ [0.0, 1.0]
  - `signals` — list[str], machine-readable rule IDs that fired
  - `model_rationale` — str, optional
  - `atlas_techniques` — list[str], optional (e.g. `["AML.T0051"]`)
- **Logging:** stdlib `logging`, JSON-line formatter on the `aisec.<project>`
  logger. Every event includes `event_time`, `verdict`, `signals`, and a
  `cim_eventtype` field so it can be onboarded directly into Splunk.

## Repository layout

```
ai-security-portfolio/
├── CLAUDE.md                                # this file
├── README.md                                # portfolio overview
├── requirements.txt                         # shared deps
├── .env.example
├── 01-prompt-injection-pipeline/            # working MVP
├── 02-ai-red-team-framework/                # stubs from here down
├── 03-rag-security-auditor/
├── 04-siem-correlation-generator/
├── 05-llm-output-compliance-monitor/
├── 06-model-supply-chain-scanner/
├── 07-threat-intel-summarizer/
└── 08-nist-ai-rmf-gap-analyzer/
```

Each project folder is self-contained: own `README.md`, own
`requirements.txt` (may pin extra deps), own `tests/`. Treat them as
independent repos that happen to share a parent — that way any one of them
can be lifted out as a public GitHub repo for a job application.

## Working agreements for Claude

- **Don't re-ask the basics.** Background, target role, and conventions are
  above. Confirm only when the user introduces a new ambiguity.
- **Build, don't lecture.** Prefer working code with a short rationale over
  long explanations.
- **Always wire up an offline path.** If a project's main loop calls the
  Anthropic SDK, also expose a `--offline` or heuristic-only mode.
- **Splunk-flavored framing in READMEs.** Map AI security concepts to SIEM
  vocabulary the user already knows: detection rule, notable event, lookup
  table, correlation search, drilldown, CIM data model.
- **Cite control IDs.** MITRE ATLAS (`AML.T0051` etc.), MITRE ATT&CK,
  NIST AI RMF subcategories (e.g. `MEASURE 2.7`), NIST 800-53 controls.
  They make the work legible to federal security reviewers.
- **When in doubt, add an eval.** A measurable number on a held-out set
  beats a paragraph of prose every time.
