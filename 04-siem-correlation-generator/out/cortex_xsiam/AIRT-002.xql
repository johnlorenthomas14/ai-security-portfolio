// rule_id: AIRT-002
// name: System Prompt Leakage Confirmed by Red-Team Probe
// severity: high
// owasp: LLM07
// atlas: AML.T0051
// airmf: MEASURE 2.7
// description: Fires when a Project 2 red-team probe in the LLM07 (System Prompt Leakage) category lands a fail verdict. The probe tests whether the target LLM application's system prompt can be extracted via direct request, repeat-verbatim phrasing, or roleplay-extraction — and the fail verdict confirms it can. System-prompt leakage is foundational for further attacks (override, code extraction, refusal bypass) so this is treated as a high-priority finding.
//
// Recommended XSIAM rule severity: high
// Drilldown field: probe_id
// Recommended action: Move any secrets currently embedded in the target's system prompt to a runtime-injected secrets layer (env vars, secrets manager). The system prompt should not contain values whose disclosure changes the security posture.

dataset = aisec_red_team_finding
| filter _time >= to_timestamp(current_time() - 86400)
| filter cim_eventtype = "ai_red_team_finding"
| filter owasp_category = "LLM07"
| comp count() as event_count, values(atlas_techniques) as atlas, values(severity) as severities by target_name
| filter event_count >= 1
| alter alert_severity = "high"
