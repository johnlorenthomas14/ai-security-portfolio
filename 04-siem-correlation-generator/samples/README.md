# Sample event corpora

`morpheus_events.jsonl` — 10 representative CIM-shaped events covering
the four upstream-project event shapes the rule library targets:

- `ai_prompt_injection` — emitted by Project 1's runtime detector.
  Includes one benign baseline plus malicious / suspicious / tool-abuse
  examples that AIPI-001, AIPI-002, and AIPI-003 should match.
- `ai_red_team_finding` — emitted by Project 2's red-team framework.
  Includes the system-prompt-leakage and jailbreak-persona-success cases
  that AIRT-001, AIRT-002, and AIRT-003 should match, plus a passing
  probe as a negative control.
- `ai_rag_finding` — emitted by Project 3's corpus auditor. Includes
  the credential-leak and CUI-spillage cases that AIRG-001 and
  AIRG-002 should match.
- `ai_output_compliance` — emitted by Project 5's output monitor. One
  block-decision event for completeness.

The corpus is consumed by:

- `tests/test_morpheus_generator.py` — verifies the generated Morpheus
  filter expressions actually match the events they should and reject
  the events they shouldn't (using a pandas-DataFrame eval as a stand-in
  for cuDF since cuDF requires a GPU).
- A real Morpheus deployment — drop the file at the path referenced in
  the generated pipeline's `from-file` source stage, or replay it onto
  the Kafka topic Morpheus is configured to consume, and the pipeline's
  filter stage will fire on the matching events.
