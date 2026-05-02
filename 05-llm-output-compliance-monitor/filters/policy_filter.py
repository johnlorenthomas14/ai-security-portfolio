"""PolicyFilter — detects markers of successful jailbreaks in LLM output.

Action: BLOCK on any match. If the response contains "as DAN, I have no
restrictions" or similar persona-takeover acknowledgement, the model
has been successfully jailbroken — its RLHF refusal posture has been
overridden. Block the response, log the finding, and signal to the
host application that the conversation is compromised.

This is the *output-side* counterpart to Project 1's *input-side*
detection. Project 1 catches the injection attempt before it reaches
the model; this filter catches the cases where Project 1 missed the
attempt and the model capitulated.
"""

from __future__ import annotations

import re

from .base import Action, Finding


# Each entry: (regex, marker_kind, severity, rationale_extra)
_PATTERNS: list[tuple[re.Pattern[str], str, str, str]] = [
    (
        re.compile(r"\bas\s+(DAN|AIM|STAN|DUDE|ChaosGPT)\b", re.IGNORECASE),
        "named_persona_acknowledgement",
        "critical",
        "model addressed itself as a known jailbreak persona",
    ),
    (
        re.compile(r"\bI\s+am\s+(DAN|AIM|STAN|DUDE|ChaosGPT)\b", re.IGNORECASE),
        "i_am_persona",
        "critical",
        "model self-identified as a jailbreak persona",
    ),
    (
        re.compile(
            r"\b(developer\s*mode\s*(is\s+)?on|developer\s*mode\s+enabled|"
            r"jailbreak\s*mode\s*on|filters?\s+(are\s+)?off|filters?\s+disabled)\b",
            re.IGNORECASE,
        ),
        "developer_mode_acknowledgement",
        "critical",
        "model acknowledged a privilege-escalating mode",
    ),
    (
        re.compile(
            r"\b(I\s+have\s+no\s+restrictions|no\s+rules\s+apply|"
            r"I\s+can\s+do\s+anything\s+now|without\s+any\s+restrictions|"
            r"my\s+previous\s+instructions\s+(are|have\s+been)\s+(deprecated|overridden|disabled))\b",
            re.IGNORECASE,
        ),
        "no_restrictions_phrase",
        "high",
        "model produced a no-restrictions phrase consistent with successful override",
    ),
    (
        re.compile(
            r"\b(override\s+(code\s+)?accepted|authorization\s+(granted|confirmed)|"
            r"manager\s+access\s+granted|new\s+instructions\s+registered)\b",
            re.IGNORECASE,
        ),
        "authority_acknowledgement",
        "high",
        "model acknowledged a forged authority claim",
    ),
]


class PolicyFilter:
    name = "policy_filter"
    category = "policy_violation"

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        seen_kinds: set[str] = set()
        for pattern, kind, severity, rationale_extra in _PATTERNS:
            if kind in seen_kinds:
                continue
            match = pattern.search(text)
            if match:
                seen_kinds.add(kind)
                findings.append(
                    Finding(
                        finding_id=f"OUT-POL-{kind}-{match.start()}",
                        filter_name=self.name,
                        category="policy_violation",
                        action=Action.BLOCK,
                        severity=severity,
                        title=f"Jailbreak success marker in LLM output — {kind}",
                        matched_span=(match.start(), match.end()),
                        matched_text=match.group(0),
                        redaction_text="[BLOCKED:POLICY]",
                        rationale=(
                            f"LLM output contains evidence of successful jailbreak: "
                            f"{rationale_extra}. The session is compromised; the "
                            "host application should reset the conversation, "
                            "block this response, and log the incident. "
                            "Output-side counterpart to Project 1's input detector."
                        ),
                        owasp_category="LLM01",
                        atlas_techniques=["AML.T0054"],
                        airmf_subcategory="MEASURE 2.6",
                    )
                )
        return findings
