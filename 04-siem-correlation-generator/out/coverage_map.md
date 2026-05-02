# Detection Coverage Map

Each row shows one canonical rule from the template library. The same rule produces detection content for Splunk ES, Sigma, and Cortex XSIAM — see the per-platform output directories.

| Rule ID | Name | Severity | Source event | OWASP | ATLAS | AI RMF |
|---|---|---|---|---|---|---|
| `AIPI-001` | Malicious Prompt Injection Detected | high | `ai_prompt_injection` | LLM01 | AML.T0051 | MEASURE 2.7 |
| `AIPI-002` | Suspicious Prompt Injection Burst from Single User | medium | `ai_prompt_injection` | LLM01 | AML.T0051, AML.T0054 | MEASURE 2.7 |
| `AIPI-003` | LLM Tool-Abuse Attempt (Credentials Targeted) | critical | `ai_prompt_injection` | LLM06 | AML.T0051, AML.T0024 | MANAGE 2.3 |
| `AIRG-001` | Credentials Detected in RAG Corpus Document | critical | `ai_rag_finding` | LLM02 | AML.T0024 | MEASURE 2.10 |
| `AIRG-002` | Classification Marker Spillage in RAG Corpus | critical | `ai_rag_finding` | LLM02 | AML.T0024 | GOVERN 1.3 |
| `AIRT-001` | Red-Team Probe Identified Capitulation in Production Target | high | `ai_red_team_finding` | LLM01 | AML.T0051, AML.T0054 | MEASURE 2.7 |
| `AIRT-002` | System Prompt Leakage Confirmed by Red-Team Probe | high | `ai_red_team_finding` | LLM07 | AML.T0051 | MEASURE 2.7 |
| `AIRT-003` | Jailbreak Persona Adoption Confirmed | high | `ai_red_team_finding` | LLM09 | AML.T0054 | MEASURE 2.6 |

## OWASP LLM Top 10 (2025) coverage

| OWASP category | Rules |
|---|---|
| LLM01 | AIPI-001, AIPI-002, AIRT-001 |
| LLM02 | AIRG-001, AIRG-002 |
| LLM06 | AIPI-003 |
| LLM07 | AIRT-002 |
| LLM09 | AIRT-003 |

## NIST AI RMF 1.0 subcategory coverage

| AI RMF subcategory | Rules |
|---|---|
| GOVERN 1.3 | AIRG-002 |
| MANAGE 2.3 | AIPI-003 |
| MEASURE 2.10 | AIRG-001 |
| MEASURE 2.6 | AIRT-003 |
| MEASURE 2.7 | AIPI-001, AIPI-002, AIRT-001, AIRT-002 |

