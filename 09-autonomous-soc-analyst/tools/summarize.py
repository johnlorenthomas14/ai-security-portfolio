"""SummarizeTool — the agent's clean-triage exit.

Calling this tool ends the agent loop with verdict=triaged. The agent
uses it when investigation is complete and a final analyst-readable
summary is ready. The summary text + any structured findings collected
during the loop become the TriageReport's published content.
"""

from __future__ import annotations

from typing import Any


class SummarizeTool:
    name = "summarize"
    description = (
        "Produce the final analyst summary for the current notable and "
        "terminate triage. Call this tool when investigation has produced "
        "enough context to either close the notable as benign / "
        "false-positive or produce a confirmed finding with recommended "
        "next steps. Calling this tool terminates the triage with "
        "verdict=triaged."
    )
    parameters = {
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["confirmed_malicious", "suspicious", "false_positive", "benign"],
                "description": "The triage verdict for the notable.",
            },
            "summary": {
                "type": "string",
                "description": (
                    "Free-text analyst-readable summary of the investigation "
                    "and conclusion. 2-4 sentences."
                ),
            },
            "key_evidence": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Bullet-pointed key evidence supporting the verdict — "
                    "matched STIX IDs, IOC enrichment results, related "
                    "Splunk events, ATLAS techniques, etc."
                ),
            },
            "recommended_action": {
                "type": "string",
                "description": (
                    "Recommended next step. May be 'close as false positive', "
                    "'monitor for repeat occurrences', etc. Use the "
                    "escalate_to_human tool instead if action requires "
                    "human authorization."
                ),
            },
        },
        "required": ["verdict", "summary"],
    }

    def invoke(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return {
            "summarized": True,
            "verdict": str(arguments.get("verdict", "suspicious")).strip(),
            "summary": str(arguments.get("summary", "")).strip(),
            "key_evidence": list(arguments.get("key_evidence", []) or []),
            "recommended_action": str(arguments.get("recommended_action", "")).strip(),
        }
