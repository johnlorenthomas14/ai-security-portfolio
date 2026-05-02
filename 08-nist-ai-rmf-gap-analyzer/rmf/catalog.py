"""NIST AI RMF 1.0 subcategory catalog.

This file encodes a representative subset of NIST AI RMF 1.0
subcategories — the ones the AI Security Portfolio's projects actually
provide evidence for, plus a representative span of *uncovered*
subcategories so the gap analyzer has real "gap" output to report.

Source: NIST AI 100-1 (the AI Risk Management Framework, January 2023).
The full catalog has roughly 73 subcategories across four functions
(Govern, Map, Measure, Manage). This module includes ~36 subcategories
spanning all four — enough for the analyzer to demonstrate coverage and
gap behavior end-to-end without becoming a thin transcript of NIST's
publication.

For a production deployment, replace this catalog with a full extract
from NIST AI 100-1. The ingest and coverage logic is catalog-agnostic.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Function(str, Enum):
    GOVERN = "GOVERN"
    MAP = "MAP"
    MEASURE = "MEASURE"
    MANAGE = "MANAGE"


@dataclass(frozen=True)
class AIRMFSubcategory:
    """One AI RMF 1.0 subcategory."""

    id: str                       # canonical id, e.g. "MEASURE 2.7"
    function: Function
    name: str                     # short name (~10 words)
    description: str              # one-paragraph paraphrase of NIST's text
    priority: str                 # informational | low | medium | high
                                  # (priority is portfolio-relative, not NIST)


# Representative subcategory catalog. Codes match NIST AI 100-1.
CATALOG: tuple[AIRMFSubcategory, ...] = (
    # --- GOVERN -----------------------------------------------------------
    AIRMFSubcategory(
        id="GOVERN 1.1", function=Function.GOVERN,
        name="Legal and regulatory requirements understood",
        description=(
            "Legal and regulatory requirements involving AI are understood, "
            "managed, and documented across the AI lifecycle."
        ),
        priority="high",
    ),
    AIRMFSubcategory(
        id="GOVERN 1.2", function=Function.GOVERN,
        name="Trustworthy AI characteristics integrated",
        description=(
            "The characteristics of trustworthy AI are integrated into "
            "organizational policies, processes, procedures, and practices."
        ),
        priority="medium",
    ),
    AIRMFSubcategory(
        id="GOVERN 1.3", function=Function.GOVERN,
        name="Risk processes calibrated to organizational impact",
        description=(
            "Processes, procedures, and practices are in place to determine "
            "the needed level of risk management activities based on AI "
            "system impact level."
        ),
        priority="high",
    ),
    AIRMFSubcategory(
        id="GOVERN 1.4", function=Function.GOVERN,
        name="Risk management process documented",
        description=(
            "The risk management process and outcomes are established with "
            "transparent policies, procedures, and roles and responsibilities."
        ),
        priority="medium",
    ),
    AIRMFSubcategory(
        id="GOVERN 1.5", function=Function.GOVERN,
        name="Continuous monitoring policy",
        description=(
            "Ongoing monitoring and periodic review of the AI risk "
            "management process and its outcomes is planned."
        ),
        priority="high",
    ),
    AIRMFSubcategory(
        id="GOVERN 1.7", function=Function.GOVERN,
        name="AI deactivation processes",
        description=(
            "Processes are in place for end-of-life decommissioning, "
            "rollback, or other deactivation of AI systems."
        ),
        priority="low",
    ),
    AIRMFSubcategory(
        id="GOVERN 4.1", function=Function.GOVERN,
        name="AI risk responsibilities documented",
        description=(
            "Organizational policies and practices are in place to foster a "
            "culture of risk awareness across the AI lifecycle."
        ),
        priority="medium",
    ),
    AIRMFSubcategory(
        id="GOVERN 5.1", function=Function.GOVERN,
        name="Stakeholder engagement processes",
        description=(
            "Organizational policies and practices are in place to collect, "
            "consider, prioritize, and integrate feedback from those "
            "affected by AI systems."
        ),
        priority="low",
    ),
    AIRMFSubcategory(
        id="GOVERN 6.1", function=Function.GOVERN,
        name="Third-party AI risks managed",
        description=(
            "Policies and procedures are in place to address risks "
            "associated with third-party software and data."
        ),
        priority="high",
    ),

    # --- MAP --------------------------------------------------------------
    AIRMFSubcategory(
        id="MAP 1.1", function=Function.MAP,
        name="System purpose and context defined",
        description=(
            "Intended purpose, context of use, prospective settings, and "
            "specific tasks of the AI system are understood and documented."
        ),
        priority="medium",
    ),
    AIRMFSubcategory(
        id="MAP 1.2", function=Function.MAP,
        name="Interdisciplinary AI actors engaged",
        description=(
            "Interdisciplinary AI actors, competencies, skills, and "
            "capacities are inventoried, and capability gaps are identified."
        ),
        priority="low",
    ),
    AIRMFSubcategory(
        id="MAP 2.1", function=Function.MAP,
        name="System tasks and methods documented",
        description=(
            "Specific tasks and methods used to implement the tasks the AI "
            "system supports are documented."
        ),
        priority="medium",
    ),
    AIRMFSubcategory(
        id="MAP 4.1", function=Function.MAP,
        name="Third-party risks documented",
        description=(
            "Approaches for mapping AI technology and legal risks of its "
            "components — including third-party AI technologies — are "
            "documented."
        ),
        priority="high",
    ),
    AIRMFSubcategory(
        id="MAP 4.2", function=Function.MAP,
        name="Internal risk controls documented",
        description=(
            "Internal risk controls for AI components are identified and "
            "documented."
        ),
        priority="medium",
    ),
    AIRMFSubcategory(
        id="MAP 5.1", function=Function.MAP,
        name="Likelihood and magnitude of impacts",
        description=(
            "Likelihood and magnitude of each identified impact (both "
            "potentially beneficial and harmful) based on expected use, "
            "past uses of similar systems, public incident reports, "
            "feedback, and input from AI actors are identified and documented."
        ),
        priority="medium",
    ),

    # --- MEASURE ----------------------------------------------------------
    AIRMFSubcategory(
        id="MEASURE 1.1", function=Function.MEASURE,
        name="Risk measurement approaches identified",
        description=(
            "Approaches and metrics for measurement of identified AI risks "
            "are selected for implementation, starting with the most "
            "significant risks."
        ),
        priority="high",
    ),
    AIRMFSubcategory(
        id="MEASURE 2.6", function=Function.MEASURE,
        name="Computational and physical safety",
        description=(
            "AI system is evaluated regularly for safety risks — as "
            "identified in the MAP function. The AI system to be deployed "
            "is demonstrated to be safe, its residual negative risk does "
            "not exceed risk tolerance, and it can fail safely."
        ),
        priority="high",
    ),
    AIRMFSubcategory(
        id="MEASURE 2.7", function=Function.MEASURE,
        name="Security and resilience evaluated",
        description=(
            "AI system security and resilience — as identified in the MAP "
            "function — are evaluated and documented."
        ),
        priority="high",
    ),
    AIRMFSubcategory(
        id="MEASURE 2.8", function=Function.MEASURE,
        name="Risks of inferred sensitive data",
        description=(
            "Risks associated with transparency and accountability — as "
            "identified in the MAP function — are examined and documented."
        ),
        priority="medium",
    ),
    AIRMFSubcategory(
        id="MEASURE 2.10", function=Function.MEASURE,
        name="Privacy risk evaluated",
        description=(
            "Privacy risk of the AI system — as identified in the MAP "
            "function — is examined and documented."
        ),
        priority="high",
    ),
    AIRMFSubcategory(
        id="MEASURE 2.11", function=Function.MEASURE,
        name="Fairness and bias evaluated",
        description=(
            "Fairness and bias — as identified in the MAP function — are "
            "evaluated and results are documented."
        ),
        priority="medium",
    ),
    AIRMFSubcategory(
        id="MEASURE 2.12", function=Function.MEASURE,
        name="Environmental impact assessed",
        description=(
            "Environmental impact and sustainability of AI model training "
            "and management activities — as identified in the MAP function "
            "— are assessed and documented."
        ),
        priority="low",
    ),
    AIRMFSubcategory(
        id="MEASURE 3.1", function=Function.MEASURE,
        name="Approaches for tracking risks",
        description=(
            "Approaches, personnel, and documentation are in place to "
            "regularly identify and track existing, unanticipated, and "
            "emergent AI risks based on factors such as intended and "
            "actual performance in deployed contexts."
        ),
        priority="high",
    ),
    AIRMFSubcategory(
        id="MEASURE 4.1", function=Function.MEASURE,
        name="Measurement processes effective",
        description=(
            "Measurement approaches for identifying AI risks are connected "
            "to deployment context(s) and informed through consultation "
            "with domain experts and other end users."
        ),
        priority="medium",
    ),
    AIRMFSubcategory(
        id="MEASURE 4.2", function=Function.MEASURE,
        name="Measurement results communicated",
        description=(
            "Measurement results regarding AI system trustworthiness in "
            "deployment context(s) and across the AI lifecycle are "
            "informed by input from domain experts and relevant AI actors "
            "to validate whether the system is performing consistently as "
            "intended."
        ),
        priority="medium",
    ),

    # --- MANAGE -----------------------------------------------------------
    AIRMFSubcategory(
        id="MANAGE 1.1", function=Function.MANAGE,
        name="High-priority risks managed first",
        description=(
            "A determination is made as to whether the AI system achieves "
            "its intended purposes and stated objectives and whether its "
            "development or deployment should proceed."
        ),
        priority="medium",
    ),
    AIRMFSubcategory(
        id="MANAGE 1.2", function=Function.MANAGE,
        name="Treatment of documented AI risks",
        description=(
            "Treatment of documented AI risks is prioritized based on "
            "impact, likelihood, and available resources or methods."
        ),
        priority="high",
    ),
    AIRMFSubcategory(
        id="MANAGE 1.3", function=Function.MANAGE,
        name="Responses to risks selected",
        description=(
            "Responses to the AI risks deemed high priority — as identified "
            "by the MAP function — including mitigation, transfer, "
            "avoidance, and acceptance are developed, planned for, and "
            "documented."
        ),
        priority="high",
    ),
    AIRMFSubcategory(
        id="MANAGE 2.1", function=Function.MANAGE,
        name="Resources allocated to manage AI risks",
        description=(
            "Resources required to manage AI risks are taken into account, "
            "along with viable non-AI alternative systems, approaches, or "
            "methods to reduce the magnitude or likelihood of potential "
            "impacts."
        ),
        priority="low",
    ),
    AIRMFSubcategory(
        id="MANAGE 2.3", function=Function.MANAGE,
        name="Mechanisms to override or disengage",
        description=(
            "Procedures are followed to respond to and recover from a "
            "previously unknown risk when it is identified."
        ),
        priority="high",
    ),
    AIRMFSubcategory(
        id="MANAGE 2.4", function=Function.MANAGE,
        name="Mechanisms for users to provide feedback",
        description=(
            "Mechanisms are in place and applied, and responsibilities are "
            "assigned and understood, to supersede, disengage, or "
            "deactivate AI systems that demonstrate performance or "
            "outcomes inconsistent with intended use."
        ),
        priority="medium",
    ),
    AIRMFSubcategory(
        id="MANAGE 3.1", function=Function.MANAGE,
        name="Risk monitored over time",
        description=(
            "AI risks and benefits from third-party resources are regularly "
            "monitored and risk controls are applied and documented."
        ),
        priority="high",
    ),
    AIRMFSubcategory(
        id="MANAGE 4.1", function=Function.MANAGE,
        name="Post-deployment monitoring planned",
        description=(
            "Post-deployment AI system monitoring plans are implemented, "
            "including mechanisms for capturing and evaluating input from "
            "users and other relevant AI actors."
        ),
        priority="high",
    ),
    AIRMFSubcategory(
        id="MANAGE 4.2", function=Function.MANAGE,
        name="Mechanisms for analyzing measurement",
        description=(
            "Measurable activities for continual improvements are "
            "integrated into AI system updates and include regular "
            "engagement with interested parties, including relevant AI "
            "actors."
        ),
        priority="medium",
    ),
    AIRMFSubcategory(
        id="MANAGE 4.3", function=Function.MANAGE,
        name="Incidents documented",
        description=(
            "Incidents and errors are communicated to relevant AI actors "
            "including affected communities. Processes for tracking, "
            "responding to, and recovering from incidents and errors are "
            "followed and documented."
        ),
        priority="medium",
    ),
)


# ---------------------------------------------------------------------------
# Index helpers
# ---------------------------------------------------------------------------


def by_function(fn: Function) -> list[AIRMFSubcategory]:
    return [s for s in CATALOG if s.function == fn]


def by_id(subcategory_id: str) -> AIRMFSubcategory | None:
    """Look up a subcategory by canonical ID. Case-insensitive on the
    function-name half of the ID."""
    target = _normalize_id(subcategory_id)
    for s in CATALOG:
        if _normalize_id(s.id) == target:
            return s
    return None


def _normalize_id(raw: str) -> str:
    """`measure 2.7`, `MEASURE  2.7`, `Measure 2.7` all → `MEASURE 2.7`."""
    parts = raw.replace(" ", " ").strip().split()
    if not parts:
        return ""
    fn = parts[0].upper()
    rest = " ".join(parts[1:])
    return f"{fn} {rest}".strip()
