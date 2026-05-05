"""Notable loader — reads notable events from various source files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator


def load_notables(source: Path | str) -> list[dict[str, Any]]:
    """Load notable events from one source. Accepted shapes:

      - JSONL file with one notable per line.
      - JSON file with shape ``{"events": [...]}`` (Project 7's notables).
      - JSON file with shape ``{"findings": [...]}`` (Projects 2/3/6).
      - Directory: load every recognized file inside, recursively flatten.
    """
    p = Path(source)
    if p.is_dir():
        out: list[dict[str, Any]] = []
        for f in sorted(p.rglob("*")):
            if f.is_file() and f.suffix.lower() in {".json", ".jsonl"}:
                out.extend(load_notables(f))
        return out

    if not p.exists():
        return []

    if p.suffix.lower() == ".jsonl":
        return list(_iter_jsonl(p))

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []

    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        for key in ("events", "findings", "notables"):
            if key in data and isinstance(data[key], list):
                return [d for d in data[key] if isinstance(d, dict)]
    return []


def _iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj
