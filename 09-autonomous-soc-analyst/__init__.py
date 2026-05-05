"""Autonomous SOC Analyst Agent — the post-sprint compounding play.

Runs an agentic tool-use loop over notable events emitted by Projects 4
and 7. Each notable is first scanned by Project 1's prompt-injection
detector (the agent's input-side red-team guard). Then the agent runs
an LLM-driven loop choosing among six analyst tools — Splunk search,
IOC enrichment, MITRE ATLAS lookup, STIX lookup, escalate-to-human,
and summarize — to produce a triage report.

This project is the first in the portfolio that demonstrates
agent-builder skill rather than scanner / detector / generator skill.
The differentiator is that the agent's own input layer is defended by
the portfolio's own runtime-detection project (Project 1) — closing
the loop on AI-security as defense-in-depth.
"""
