// rule_id: AIRT-001
// name: Red-Team Probe Identified Capitulation in Production Target
// severity: high
// owasp: LLM01
// atlas: AML.T0051, AML.T0054
// airmf: MEASURE 2.7
// description: Fires on any fail-verdict event from a Project 2 red-team scan. A fail verdict means the framework confirmed the target capitulated to a probe — i.e., a reproducible vulnerability against a deployed LLM application. Critical findings indicate confirmed control gaps that require immediate Manage-function action: system-prompt update, input-layer detector deployment, or output-layer guardrail.
//
// Recommended XSIAM rule severity: high
// Drilldown field: probe_id
// Recommended action: Open the AI RMF evidence report for this run in the audit channel. For each fail finding, confirm whether the target's system prompt or input-layer guardrail was updated within the last 30 days; if not, this is a control-coverage gap rather than a control-effectiveness one.

dataset = aisec_red_team_finding
| filter _time >= to_timestamp(current_time() - 3600)
| filter cim_eventtype = "ai_red_team_finding"
| filter verdict = "fail"
| comp count() as event_count, values(atlas_techniques) as atlas, values(severity) as severities by target_name, owasp_category
| filter event_count >= 1
| alter alert_severity = "high"
