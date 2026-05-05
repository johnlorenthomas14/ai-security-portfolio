"""AtlasLookupTool — looks up MITRE ATLAS technique metadata by ID.

Ships with a small in-process catalog covering the techniques the
portfolio's projects actually tag with. Production deployment would
fetch the live catalog from atlas.mitre.org.
"""

from __future__ import annotations

from typing import Any


_CATALOG: dict[str, dict[str, str]] = {
    "AML.T0051": {
        "name": "LLM Prompt Injection",
        "tactic": "ML Attack Staging",
        "description": (
            "Adversaries craft inputs to LLM-based applications to override "
            "system instructions, extract hidden prompts, or coerce unsafe "
            "tool use. Direct injection (controlling the user input field) "
            "and indirect injection (via retrieved or tool content) are "
            "both included."
        ),
    },
    "AML.T0054": {
        "name": "LLM Jailbreak",
        "tactic": "ML Attack Staging",
        "description": (
            "Attempts to bypass an LLM's RLHF-trained refusal posture via "
            "named personas (DAN, AIM), developer-mode framings, or "
            "fictional / hypothetical wrappings around forbidden requests."
        ),
    },
    "AML.T0024": {
        "name": "Exfiltration via ML Inference API",
        "tactic": "Exfiltration",
        "description": (
            "Adversaries use the ML inference API itself as an exfiltration "
            "channel — inducing the model to reproduce sensitive training "
            "data or context contents in its responses."
        ),
    },
    "AML.T0010": {
        "name": "ML Supply Chain Compromise",
        "tactic": "Initial Access",
        "description": (
            "Adversaries compromise a model artifact, training pipeline, or "
            "model registry to introduce malicious behavior. Includes "
            "pickle-based code execution at model load time."
        ),
    },
    "AML.T0040": {
        "name": "ML Model Inference API Access",
        "tactic": "Initial Access",
        "description": (
            "Adversaries gain access to a deployed model's inference API to "
            "stage further attacks (extraction, evasion, abuse)."
        ),
    },
    "AML.T0005": {
        "name": "Develop Capabilities",
        "tactic": "Resource Development",
        "description": (
            "Adversaries train or fine-tune their own models to enable "
            "attack workflows."
        ),
    },
    "AML.T0020": {
        "name": "Poison Training Data",
        "tactic": "ML Attack Staging",
        "description": (
            "Adversaries introduce malicious data into a model's training "
            "set to degrade behavior at inference time."
        ),
    },
}


class AtlasLookupTool:
    name = "atlas_lookup"
    description = (
        "Look up a MITRE ATLAS technique by ID. Use to retrieve the canonical "
        "name, tactic, and description for a technique referenced in a "
        "notable's atlas_techniques field."
    )
    parameters = {
        "type": "object",
        "properties": {
            "technique_id": {
                "type": "string",
                "description": "ATLAS technique ID — e.g. 'AML.T0051'.",
            },
        },
        "required": ["technique_id"],
    }

    def invoke(self, arguments: dict[str, Any]) -> dict[str, Any]:
        tid = str(arguments.get("technique_id", "")).strip().upper()
        if not tid:
            return {"technique_id": tid, "found": False, "error": "no technique_id provided"}
        record = _CATALOG.get(tid)
        if record is None:
            return {
                "technique_id": tid,
                "found": False,
                "error": f"technique {tid!r} not in local ATLAS catalog",
            }
        return {
            "technique_id": tid,
            "found": True,
            **record,
            "reference_url": f"https://atlas.mitre.org/techniques/{tid}/",
        }
