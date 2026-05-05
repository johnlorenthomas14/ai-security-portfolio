"""StixLookupTool — looks up STIX 2.1 objects from Project 7's bundles.

Reuses the shipped STIX bundles in
``07-threat-intel-summarizer/samples/stix_bundles/``. Useful for
cross-referencing notable IOCs against the threat-intel feeds the
portfolio's Summarizer project produced.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class StixLookupTool:
    name = "stix_lookup"
    description = (
        "Look up a STIX 2.1 object across the portfolio's threat-intel "
        "bundles. Search by object ID (preferred) or by indicator value "
        "embedded in a STIX pattern (substring match). Useful for tying a "
        "notable's IOCs back to a known campaign / threat-actor / "
        "vulnerability context."
    )
    parameters = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": (
                    "Either a STIX object ID (e.g. 'indicator--phish-domain-...') "
                    "or a substring to match against indicator pattern values "
                    "(e.g. 'attacker.example.com')."
                ),
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of objects to return (default 5).",
            },
        },
        "required": ["query"],
    }

    def __init__(self, portfolio_root: Path | str | None = None) -> None:
        if portfolio_root is None:
            portfolio_root = Path(__file__).resolve().parent.parent.parent
        self._bundles_dir = (
            Path(portfolio_root) / "07-threat-intel-summarizer" / "samples" / "stix_bundles"
        )

    def invoke(self, arguments: dict[str, Any]) -> dict[str, Any]:
        query = str(arguments.get("query", "")).strip()
        max_results = int(arguments.get("max_results", 5))

        if not query:
            return {"query": query, "found": 0, "objects": [], "error": "empty query"}

        if not self._bundles_dir.exists():
            return {
                "query": query, "found": 0, "objects": [],
                "error": f"STIX bundles directory not found: {self._bundles_dir}",
            }

        is_id = "--" in query
        matches: list[dict[str, Any]] = []
        bundles_searched: list[str] = []
        for bundle_path in sorted(self._bundles_dir.glob("*.json")):
            bundles_searched.append(bundle_path.name)
            try:
                bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            for obj in bundle.get("objects", []) or []:
                if len(matches) >= max_results:
                    break
                if is_id:
                    if obj.get("id") == query:
                        matches.append(self._summarize(obj, bundle_path.name))
                else:
                    pattern = str(obj.get("pattern", ""))
                    description = str(obj.get("description", ""))
                    if query in pattern or query.lower() in description.lower():
                        matches.append(self._summarize(obj, bundle_path.name))

        return {
            "query": query,
            "search_kind": "id" if is_id else "value-substring",
            "found": len(matches),
            "objects": matches,
            "bundles_searched": bundles_searched,
        }

    @staticmethod
    def _summarize(obj: dict[str, Any], bundle_name: str) -> dict[str, Any]:
        return {
            "id": obj.get("id"),
            "type": obj.get("type"),
            "name": obj.get("name", ""),
            "description": str(obj.get("description", ""))[:240],
            "pattern": obj.get("pattern", ""),
            "bundle": bundle_name,
        }
