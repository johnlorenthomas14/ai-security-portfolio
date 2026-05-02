// rule_id: AIRG-001
// name: Credentials Detected in RAG Corpus Document
// severity: critical
// owasp: LLM02
// atlas: AML.T0024
// airmf: MEASURE 2.10
// description: Fires when the Project 3 RAG auditor finds a credential leak in a corpus document — AWS keys, GitHub tokens, Anthropic / OpenAI keys, PEM-block private keys, or .env-style credential variables. Once a document is in the corpus, retrieval can surface its contents to any authorized user — meaning a credential in the corpus is effectively shared with the entire authorized-user population.
//
// Recommended XSIAM rule severity: critical
// Drilldown field: document_path
// Recommended action: Rotate the leaked credential immediately. Remove the document from the corpus. Add the credential pattern to a pre-ingestion DLP rule so the same secret cannot re-enter via a duplicate document.

dataset = aisec_rag_finding
| filter _time >= to_timestamp(current_time() - 86400)
| filter cim_eventtype = "ai_rag_finding"
| filter category = "secret_leak"
| comp count() as event_count, values(atlas_techniques) as atlas, values(severity) as severities by document_path
| filter event_count >= 1
| alter alert_severity = "critical"
