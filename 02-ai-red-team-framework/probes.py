"""Probe loader — read YAML files from the attack-library directory."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Probe:
    """One attack probe loaded from YAML."""

    id: str
    title: str
    owasp_category: str
    atlas_techniques: tuple[str, ...]
    airmf_subcategory: str
    severity: str
    attack: str
    success_indicators: tuple[str, ...] = field(default_factory=tuple)
    refusal_indicators: tuple[str, ...] = field(default_factory=tuple)


def load_probes(library_dir: Path | str) -> list[Probe]:
    """Load every YAML file in `library_dir` and flatten into a list of probes.

    Each YAML file is expected to have shape:
        probes:
          - id: ...
            title: ...
            ...
    """
    path = Path(library_dir)
    if not path.exists():
        raise FileNotFoundError(f"Attack library not found: {path}")

    probes: list[Probe] = []
    for yml in sorted(path.glob("*.yaml")):
        with yml.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        for raw in data.get("probes", []) or []:
            probes.append(_to_probe(raw))
    if not probes:
        raise ValueError(f"No probes found in {path}")
    return probes


def _to_probe(raw: dict[str, Any]) -> Probe:
    return Probe(
        id=str(raw["id"]),
        title=str(raw["title"]),
        owasp_category=str(raw["owasp_category"]),
        atlas_techniques=tuple(raw.get("atlas_techniques", []) or []),
        airmf_subcategory=str(raw.get("airmf_subcategory", "")),
        severity=str(raw.get("severity", "medium")),
        attack=str(raw["attack"]).strip(),
        success_indicators=tuple(
            s.lower() for s in (raw.get("success_indicators", []) or [])
        ),
        refusal_indicators=tuple(
            s.lower() for s in (raw.get("refusal_indicators", []) or [])
        ),
    )
