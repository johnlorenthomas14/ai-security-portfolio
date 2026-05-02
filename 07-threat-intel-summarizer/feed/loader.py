"""STIX bundle loader.

Reads STIX 2.1 JSON bundles from disk and produces normalized StixBundle
objects with every object indexed by ID for O(1) citation verification.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from .stix_types import StixBundle, StixObject


def load_bundle(path: Path | str) -> StixBundle:
    """Load one STIX 2.1 JSON bundle from disk."""
    p = Path(path)
    raw = json.loads(p.read_text(encoding="utf-8"))
    if raw.get("type") != "bundle":
        raise ValueError(f"{p} is not a STIX bundle (type != 'bundle')")

    objects: dict[str, StixObject] = {}
    for obj in raw.get("objects", []) or []:
        oid = obj.get("id")
        otype = obj.get("type")
        if not oid or not otype:
            continue
        objects[oid] = StixObject(id=oid, type=otype, raw=obj)

    return StixBundle(
        bundle_id=raw.get("id", p.stem),
        spec_version=raw.get("spec_version", "2.1"),
        objects=objects,
    )


def iter_bundles(directory: Path | str) -> Iterator[tuple[Path, StixBundle]]:
    """Yield (path, bundle) for every *.json bundle in `directory`, sorted."""
    d = Path(directory)
    for p in sorted(d.glob("*.json")):
        try:
            yield p, load_bundle(p)
        except ValueError:
            continue
