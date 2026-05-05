"""SplunkSearchTool — runs simple field=value queries against the bundled
synthetic Splunk-like event store. Mock implementation: production
deployment would dispatch to a real Splunk REST API.

The synthetic store ships in samples/synthetic_splunk_events.jsonl —
one JSON object per line, each shaped like a real
ai_prompt_injection event. The tool's query syntax is deliberately
small: comma-separated `field=value` filters, all conjunctive.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


_DEFAULT_EVENTS = Path(__file__).resolve().parent.parent / "samples" / "synthetic_splunk_events.jsonl"


class SplunkSearchTool:
    name = "splunk_search"
    description = (
        "Search the Splunk-like event store for events matching simple "
        "field=value filters. Useful for pulling related events around a "
        "user, app, src_ip, or verdict to establish context for a notable."
    )
    parameters = {
        "type": "object",
        "properties": {
            "filters": {
                "type": "string",
                "description": (
                    "Comma-separated field=value filters — e.g., "
                    "'user=alice,verdict=malicious'. All filters AND together."
                ),
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of events to return (default 10).",
            },
        },
        "required": ["filters"],
    }

    def __init__(self, events_path: Path | str | None = None) -> None:
        self._events_path = Path(events_path) if events_path else _DEFAULT_EVENTS

    def invoke(self, arguments: dict[str, Any]) -> dict[str, Any]:
        filters_raw = str(arguments.get("filters", "")).strip()
        max_results = int(arguments.get("max_results", 10))
        filters = self._parse_filters(filters_raw)

        if not self._events_path.exists():
            return {"matched": 0, "events": [], "error": "events store not available"}

        matched: list[dict[str, Any]] = []
        with self._events_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if all(self._field_matches(event, k, v) for k, v in filters.items()):
                    matched.append(event)
                if len(matched) >= max_results:
                    break

        return {
            "matched": len(matched),
            "events": matched,
            "filters_applied": filters,
        }

    # ------------------------------------------------------------------

    @staticmethod
    def _parse_filters(raw: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for clause in raw.split(","):
            if "=" not in clause:
                continue
            k, v = clause.split("=", 1)
            out[k.strip()] = v.strip().strip("\"'")
        return out

    @staticmethod
    def _field_matches(event: dict[str, Any], field: str, expected: str) -> bool:
        value = event.get(field)
        if value is None:
            return False
        if isinstance(value, list):
            return expected in value
        return str(value) == expected
