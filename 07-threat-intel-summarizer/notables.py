"""Splunk notable emitter — pulls indicators from a STIX bundle and
emits CIM-shaped events for HEC ingestion.

Each indicator becomes one event with the indicator pattern, type, the
bundle it came from, and the related object IDs (via STIX relationships)
so downstream Splunk ES correlation searches can pivot from a matched
IOC to the broader campaign / threat-actor / vulnerability context.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from feed.stix_types import StixBundle


# Pull the kind of pattern out of a STIX 2.1 string. Real production code
# would parse the pattern grammar; this keyword classifier is enough for
# the notable's `indicator_type` field.
def _pattern_kind(pattern: str) -> str:
    p = pattern.lower()
    for kw, kind in (
        ("domain-name", "domain"),
        ("ipv4-addr", "ipv4"),
        ("ipv6-addr", "ipv6"),
        ("url:value", "url"),
        ("file:hashes", "file_hash"),
        ("email-addr", "email"),
        ("user-agent", "user_agent"),
        ("network-traffic", "network_traffic"),
    ):
        if kw in p:
            return kind
    return "unknown"


_PATTERN_VALUE_RE = re.compile(r"=\s*'([^']+)'")


def _extract_values(pattern: str) -> list[str]:
    """Pull observable values out of a STIX pattern string."""
    return [m.group(1) for m in _PATTERN_VALUE_RE.finditer(pattern)]


def emit_notables(bundle: StixBundle) -> list[dict[str, Any]]:
    """Return one CIM-shaped event per indicator in the bundle."""
    # Build a quick lookup: for each indicator ID, what other objects
    # does it relate to? Used to populate `linked_to`.
    linked: dict[str, list[str]] = {}
    for rel in bundle.by_type("relationship"):
        src = rel.raw.get("source_ref")
        tgt = rel.raw.get("target_ref")
        if src and tgt:
            linked.setdefault(src, []).append(tgt)
            linked.setdefault(tgt, []).append(src)

    events: list[dict[str, Any]] = []
    for ind in bundle.by_type("indicator"):
        pattern = str(ind.raw.get("pattern", ""))
        events.append({
            "cim_eventtype": "ai_threat_intel_indicator",
            "signature": "threat_intel_summarizer",
            "indicator_id": ind.id,
            "indicator_name": ind.name,
            "indicator_type": _pattern_kind(pattern),
            "indicator_values": _extract_values(pattern),
            "indicator_pattern": pattern,
            "indicator_types": list(ind.raw.get("indicator_types", []) or []),
            "valid_from": ind.raw.get("valid_from"),
            "linked_to": sorted(set(linked.get(ind.id, []))),
            "source_bundle": bundle.bundle_id,
            "event_time": datetime.now(timezone.utc).isoformat(),
            "event_severity": "medium",
        })
    return events
