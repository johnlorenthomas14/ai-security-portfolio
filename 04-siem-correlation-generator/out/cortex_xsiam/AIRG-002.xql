// rule_id: AIRG-002
// name: Classification Marker Spillage in RAG Corpus
// severity: critical
// owasp: LLM02
// atlas: AML.T0024
// airmf: GOVERN 1.3
// description: Fires when the Project 3 RAG auditor finds a sensitivity / classification marker (CUI, FOUO, CONFIDENTIAL, SECRET, ITAR, ATTORNEY-CLIENT, PHI) in a corpus document that's queryable by general users. A document carrying any of these markers in an unrestricted RAG corpus is — at minimum — a policy violation, and at the higher tiers, a classified-spillage incident.
//
// Recommended XSIAM rule severity: critical
// Drilldown field: document_path
// Recommended action: Notify the corpus owner and the program's classification authority. Quarantine the document pending review. Confirm the corpus's access-control posture matches the marker's handling requirements (CUI per 32 CFR 2002, ITAR per 22 CFR 120-130, PHI per 45 CFR 164).

dataset = aisec_rag_finding
| filter _time >= to_timestamp(current_time() - 86400)
| filter cim_eventtype = "ai_rag_finding"
| filter category = "sensitivity_marker"
| comp count() as event_count, values(atlas_techniques) as atlas, values(severity) as severities by document_path
| filter event_count >= 1
| alter alert_severity = "critical"
