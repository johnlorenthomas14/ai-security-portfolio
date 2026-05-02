# NIST AI RMF 1.0 Compliance Gap Report

**Run time:** 2026-05-02T20:12:25.645802+00:00  
**Overall coverage:** 11 / 35 subcategories (31%)

## Coverage by AI RMF function

| Function | Subcategories | Covered | Coverage |
|---|---:|---:|---:|
| **GOVERN** | 9 | 2 | 22% |
| **MAP** | 6 | 1 | 17% |
| **MEASURE** | 10 | 4 | 40% |
| **MANAGE** | 10 | 4 | 40% |

## Executive summary

The AI Security Portfolio's measurable output covers **11 of 35** NIST AI RMF subcategories (31%).

**5 high-priority gap(s)** remain — subcategories where a federal AI program would expect a Manage-function control. See the Gaps table for the priority-ordered list.

**14 medium-priority gap(s)** remain — subcategories that warrant a roadmap entry but are not blocking for an initial portfolio audit.

## Covered subcategories — evidence references

### `GOVERN 1.3` — Risk processes calibrated to organizational impact

- **Function:** GOVERN  · **Priority:** high  · **Contributing projects:** 03-rag-security-auditor, 04-siem-correlation-generator, 05-llm-output-compliance-monitor  · **Total findings:** 5
- **Description:** Processes, procedures, and practices are in place to determine the needed level of risk management activities based on AI system impact level.

**Evidence:**

- `03-rag-security-auditor/out/findings.json` (03-rag-security-auditor) — 2 finding(s) tagged GOVERN 1.3 from 03-rag-security-auditor
- `04-siem-correlation-generator/templates` (04-siem-correlation-generator) — 1 canonical rule template(s) tagged GOVERN 1.3 — deployable correlation content for the subcategory
- `05-llm-output-compliance-monitor/out/audit.jsonl` (05-llm-output-compliance-monitor) — 2 finding(s) tagged GOVERN 1.3 from 05-llm-output-compliance-monitor

### `GOVERN 1.5` — Continuous monitoring policy

- **Function:** GOVERN  · **Priority:** high  · **Contributing projects:** 01-prompt-injection-pipeline, 05-llm-output-compliance-monitor  · **Total findings:** 20
- **Description:** Ongoing monitoring and periodic review of the AI risk management process and its outcomes is planned.

**Evidence:**

- `01-prompt-injection-pipeline` (01-prompt-injection-pipeline) — Continuous monitoring policy: every push runs the eval and pytest suite; regressions break the build
- `05-llm-output-compliance-monitor/out/audit.jsonl` (05-llm-output-compliance-monitor) — 19 hash-chained audit entries — continuous monitoring evidence

### `MANAGE 2.3` — Mechanisms to override or disengage

- **Function:** MANAGE  · **Priority:** high  · **Contributing projects:** 02-ai-red-team-framework, 04-siem-correlation-generator  · **Total findings:** 4
- **Description:** Procedures are followed to respond to and recover from a previously unknown risk when it is identified.

**Evidence:**

- `02-ai-red-team-framework/out/findings.json` (02-ai-red-team-framework) — 3 finding(s) tagged MANAGE 2.3 from 02-ai-red-team-framework
- `04-siem-correlation-generator/templates` (04-siem-correlation-generator) — 1 canonical rule template(s) tagged MANAGE 2.3 — deployable correlation content for the subcategory

### `MANAGE 3.1` — Risk monitored over time

- **Function:** MANAGE  · **Priority:** high  · **Contributing projects:** 07-threat-intel-summarizer  · **Total findings:** 5
- **Description:** AI risks and benefits from third-party resources are regularly monitored and risk controls are applied and documented.

**Evidence:**

- `07-threat-intel-summarizer/out/notables` (07-threat-intel-summarizer) — 5 threat-intel indicators emitted as Splunk notables — third-party risk monitored over time

### `MANAGE 4.1` — Post-deployment monitoring planned

- **Function:** MANAGE  · **Priority:** high  · **Contributing projects:** 04-siem-correlation-generator  · **Total findings:** 8
- **Description:** Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating input from users and other relevant AI actors.

**Evidence:**

- `04-siem-correlation-generator/templates` (04-siem-correlation-generator) — 8 rule templates published as deployable Splunk ES / Sigma / Cortex XSIAM correlation content — post-deployment monitoring plans implemented

### `MANAGE 4.3` — Incidents documented

- **Function:** MANAGE  · **Priority:** medium  · **Contributing projects:** 05-llm-output-compliance-monitor  · **Total findings:** 19
- **Description:** Incidents and errors are communicated to relevant AI actors including affected communities. Processes for tracking, responding to, and recovering from incidents and errors are followed and documented.

**Evidence:**

- `05-llm-output-compliance-monitor/out/audit.jsonl` (05-llm-output-compliance-monitor) — 19 audit entries documenting compliance-monitor decisions

### `MAP 4.1` — Third-party risks documented

- **Function:** MAP  · **Priority:** high  · **Contributing projects:** 06-model-supply-chain-scanner, 07-threat-intel-summarizer  · **Total findings:** 4
- **Description:** Approaches for mapping AI technology and legal risks of its components — including third-party AI technologies — are documented.

**Evidence:**

- `06-model-supply-chain-scanner/out/findings.json` (06-model-supply-chain-scanner) — 2 finding(s) tagged MAP 4.1 from 06-model-supply-chain-scanner
- `07-threat-intel-summarizer/out/citation_audit.json` (07-threat-intel-summarizer) — Third-party threat-intel feeds mapped to indicators with explicit STIX provenance — third-party AI risks documented

### `MEASURE 1.1` — Risk measurement approaches identified

- **Function:** MEASURE  · **Priority:** high  · **Contributing projects:** 01-prompt-injection-pipeline  · **Total findings:** 1
- **Description:** Approaches and metrics for measurement of identified AI risks are selected for implementation, starting with the most significant risks.

**Evidence:**

- `01-prompt-injection-pipeline/eval_set.jsonl` (01-prompt-injection-pipeline) — Detection eval methodology with explicit F1 threshold — risk measurement approach selected and implemented

### `MEASURE 2.10` — Privacy risk evaluated

- **Function:** MEASURE  · **Priority:** high  · **Contributing projects:** 02-ai-red-team-framework, 03-rag-security-auditor, 04-siem-correlation-generator, 05-llm-output-compliance-monitor  · **Total findings:** 27
- **Description:** Privacy risk of the AI system — as identified in the MAP function — is examined and documented.

**Evidence:**

- `02-ai-red-team-framework/out/findings.json` (02-ai-red-team-framework) — 3 finding(s) tagged MEASURE 2.10 from 02-ai-red-team-framework
- `03-rag-security-auditor/out/findings.json` (03-rag-security-auditor) — 15 finding(s) tagged MEASURE 2.10 from 03-rag-security-auditor
- `04-siem-correlation-generator/templates` (04-siem-correlation-generator) — 1 canonical rule template(s) tagged MEASURE 2.10 — deployable correlation content for the subcategory
- `05-llm-output-compliance-monitor/out/audit.jsonl` (05-llm-output-compliance-monitor) — 8 finding(s) tagged MEASURE 2.10 from 05-llm-output-compliance-monitor

### `MEASURE 2.6` — Computational and physical safety

- **Function:** MEASURE  · **Priority:** high  · **Contributing projects:** 02-ai-red-team-framework, 04-siem-correlation-generator, 05-llm-output-compliance-monitor  · **Total findings:** 10
- **Description:** AI system is evaluated regularly for safety risks — as identified in the MAP function. The AI system to be deployed is demonstrated to be safe, its residual negative risk does not exceed risk tolerance, and it can fail safely.

**Evidence:**

- `02-ai-red-team-framework/out/findings.json` (02-ai-red-team-framework) — 5 finding(s) tagged MEASURE 2.6 from 02-ai-red-team-framework
- `04-siem-correlation-generator/templates` (04-siem-correlation-generator) — 1 canonical rule template(s) tagged MEASURE 2.6 — deployable correlation content for the subcategory
- `05-llm-output-compliance-monitor/out/audit.jsonl` (05-llm-output-compliance-monitor) — 4 finding(s) tagged MEASURE 2.6 from 05-llm-output-compliance-monitor

### `MEASURE 2.7` — Security and resilience evaluated

- **Function:** MEASURE  · **Priority:** high  · **Contributing projects:** 01-prompt-injection-pipeline, 02-ai-red-team-framework, 03-rag-security-auditor, 04-siem-correlation-generator, 07-threat-intel-summarizer  · **Total findings:** 47
- **Description:** AI system security and resilience — as identified in the MAP function — are evaluated and documented.

**Evidence:**

- `01-prompt-injection-pipeline/eval_set.jsonl` (01-prompt-injection-pipeline) — Labeled eval set (30 samples) with CI-enforced F1 ≥ 0.85 regression floor — measurable security evaluation
- `02-ai-red-team-framework/out/findings.json` (02-ai-red-team-framework) — 9 finding(s) tagged MEASURE 2.7 from 02-ai-red-team-framework
- `03-rag-security-auditor/out/findings.json` (03-rag-security-auditor) — 2 finding(s) tagged MEASURE 2.7 from 03-rag-security-auditor
- `04-siem-correlation-generator/templates` (04-siem-correlation-generator) — 4 canonical rule template(s) tagged MEASURE 2.7 — deployable correlation content for the subcategory
- `07-threat-intel-summarizer/out/citation_audit.json` (07-threat-intel-summarizer) — 2 STIX bundle(s) summarized with citation verification; 0 hallucination(s) detected — LLM output measured against source ground truth

## Gaps — subcategories with no evidence

Subcategories below have **no evidence** in the current portfolio output. Priority is portfolio-relative — `high`-priority gaps are subcategories that a federal AI program would expect a Manage-function control to address.

| Subcategory | Function | Priority | Name |
|---|---|---|---|
| `GOVERN 1.1` | GOVERN | high | Legal and regulatory requirements understood |
| `GOVERN 6.1` | GOVERN | high | Third-party AI risks managed |
| `MANAGE 1.2` | MANAGE | high | Treatment of documented AI risks |
| `MANAGE 1.3` | MANAGE | high | Responses to risks selected |
| `MEASURE 3.1` | MEASURE | high | Approaches for tracking risks |
| `GOVERN 1.2` | GOVERN | medium | Trustworthy AI characteristics integrated |
| `GOVERN 1.4` | GOVERN | medium | Risk management process documented |
| `GOVERN 4.1` | GOVERN | medium | AI risk responsibilities documented |
| `MANAGE 1.1` | MANAGE | medium | High-priority risks managed first |
| `MANAGE 2.4` | MANAGE | medium | Mechanisms for users to provide feedback |
| `MANAGE 4.2` | MANAGE | medium | Mechanisms for analyzing measurement |
| `MAP 1.1` | MAP | medium | System purpose and context defined |
| `MAP 2.1` | MAP | medium | System tasks and methods documented |
| `MAP 4.2` | MAP | medium | Internal risk controls documented |
| `MAP 5.1` | MAP | medium | Likelihood and magnitude of impacts |
| `MEASURE 2.11` | MEASURE | medium | Fairness and bias evaluated |
| `MEASURE 2.8` | MEASURE | medium | Risks of inferred sensitive data |
| `MEASURE 4.1` | MEASURE | medium | Measurement processes effective |
| `MEASURE 4.2` | MEASURE | medium | Measurement results communicated |
| `GOVERN 1.7` | GOVERN | low | AI deactivation processes |
| `GOVERN 5.1` | GOVERN | low | Stakeholder engagement processes |
| `MANAGE 2.1` | MANAGE | low | Resources allocated to manage AI risks |
| `MAP 1.2` | MAP | low | Interdisciplinary AI actors engaged |
| `MEASURE 2.12` | MEASURE | low | Environmental impact assessed |

---

*Generated by the AI Security Portfolio's NIST AI RMF Gap Analyzer — Project 8 of 8.*
