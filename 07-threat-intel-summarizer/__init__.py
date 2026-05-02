"""Adaptive Threat Intelligence Summarizer.

Reads STIX 2.1 threat-intel bundles, asks Claude to produce an analyst-
readable brief with explicit citations to STIX object IDs, verifies that
every citation resolves to a real object (catching hallucinated refs),
and emits both the markdown brief and CIM-shaped Splunk notable events
for the indicators contained in the bundle.

Differentiator vs. typical "LLM summarizer" projects: every claim the
model writes is bound to a STIX object ID, and the verifier rejects
briefs that contain unresolved citations. That's the discipline a SOC
needs before it can rely on LLM-generated intel briefs.
"""
