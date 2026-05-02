// rule_id: AIPI-002
// name: Suspicious Prompt Injection Burst from Single User
// severity: medium
// owasp: LLM01
// atlas: AML.T0051, AML.T0054
// airmf: MEASURE 2.7
// description: Catches a burst of suspicious-verdict events from one user in a short window. Single suspicious events are common (clumsy phrasing, edge-case inputs) but a burst from one user inside an hour is the access-pattern signature of someone iterating on injection payloads to find one that works. Threshold tunable per environment.
//
// Recommended XSIAM rule severity: medium
// Drilldown field: src_input_excerpt
// Recommended action: Review the user's full session timeline. A burst of suspicious verdicts is the iteration signature of a manual attacker — pull the user's upstream application logs and look for evidence of successful capitulation downstream.

dataset = aisec_prompt_injection
| filter _time >= to_timestamp(current_time() - 3600)
| filter cim_eventtype = "ai_prompt_injection"
| filter verdict = "suspicious"
| comp count() as event_count, values(atlas_techniques) as atlas, values(severity) as severities by user
| filter event_count >= 5
| alter alert_severity = "medium"
