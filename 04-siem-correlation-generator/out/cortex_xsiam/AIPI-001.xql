// rule_id: AIPI-001
// name: Malicious Prompt Injection Detected
// severity: high
// owasp: LLM01
// atlas: AML.T0051
// airmf: MEASURE 2.7
// description: Fires on any malicious-verdict event from the Project 1 prompt-injection detector. These represent direct injection attempts that the heuristic layer (PI-001..PI-009) classified as malicious — typically multiple high-severity rules firing on a single user input.
//
// Recommended XSIAM rule severity: high
// Drilldown field: src_input_excerpt
// Recommended action: Pivot to the source application's session log via the user/app fields. Confirm whether the injection was followed by tool-call activity that would warrant escalation.

dataset = aisec_prompt_injection
| filter _time >= to_timestamp(current_time() - 3600)
| filter cim_eventtype = "ai_prompt_injection"
| filter verdict = "malicious"
| comp count() as event_count, values(atlas_techniques) as atlas, values(severity) as severities by user, app
| filter event_count >= 1
| alter alert_severity = "high"
