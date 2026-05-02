"""STIX 2.1 dataclasses — minimal, scoped to what we consume.

We don't try to model the full STIX spec. We model the object types this
summarizer actually inspects: indicator, threat-actor, malware,
attack-pattern, vulnerability, campaign, report, identity, relationship.
For everything else, the loader keeps the raw dict and the brief
generator can reference it by ID without needing typed accessors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# STIX 2.1 object types we care about. The loader keeps everything but
# only typed-accesses these.
KNOWN_TYPES = {
    "indicator", "threat-actor", "malware", "attack-pattern",
    "vulnerability", "campaign", "report", "identity",
    "relationship", "intrusion-set", "tool", "course-of-action",
    "observed-data", "sighting", "infrastructure",
}


@dataclass(frozen=True)
class StixObject:
    """One object from a STIX 2.1 bundle. Carries the raw dict for fields
    we don't statically model."""

    id: str                       # e.g. "indicator--abc-123"
    type: str                     # e.g. "indicator"
    raw: dict[str, Any]

    @property
    def name(self) -> str:
        return str(self.raw.get("name", "") or self.raw.get("id", ""))

    @property
    def description(self) -> str:
        return str(self.raw.get("description", ""))

    @property
    def labels(self) -> list[str]:
        return list(self.raw.get("labels", []) or [])


@dataclass
class StixBundle:
    """A loaded STIX bundle indexed by object ID."""

    bundle_id: str
    spec_version: str
    objects: dict[str, StixObject] = field(default_factory=dict)

    def __iter__(self):
        return iter(self.objects.values())

    def __len__(self) -> int:
        return len(self.objects)

    def by_type(self, stix_type: str) -> list[StixObject]:
        return [o for o in self.objects.values() if o.type == stix_type]

    def has(self, stix_id: str) -> bool:
        return stix_id in self.objects
