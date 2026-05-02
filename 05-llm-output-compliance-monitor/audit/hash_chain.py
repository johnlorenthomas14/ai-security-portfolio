"""Hash-chained, tamper-evident audit log.

Pattern: every entry's hash is bound to the previous entry's hash. A
verifier walks the file, recomputes each entry's hash, and confirms
each entry's `prev_hash` field matches the previous entry's `hash`. Any
edit to a past entry — content change, deletion, reordering — breaks
the chain and is detected at the offending index.

This is the FedRAMP-flavored differentiator. The same pattern appears
in S3 Object Lock + KMS + CloudTrail integrity, in Splunk's signed
audit log, and in any blockchain-style integrity system. Implementing
it directly in the monitor's audit path means compliance integrity is
a property of the artifact itself, not of the surrounding storage
system.

Storage format: append-only JSONL. Each line is one AuditEntry as JSON.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


GENESIS_HASH = "0" * 64  # SHA256 length


@dataclass
class AuditEntry:
    """One audit-log entry. Field order is canonical for hashing."""

    entry_id: str
    timestamp: str
    decision_verdict: str           # "pass" | "redact" | "block"
    findings: list[dict[str, Any]]  # serialized finding summaries
    response_excerpt: str           # truncated original response
    redaction_excerpt: str          # truncated post-redaction response
    prev_hash: str
    hash: str = ""

    def compute_hash(self) -> str:
        """Recompute this entry's hash from its content fields."""
        # Deterministic JSON for hashing — sort_keys keeps it stable.
        body = {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "decision_verdict": self.decision_verdict,
            "findings": self.findings,
            "response_excerpt": self.response_excerpt,
            "redaction_excerpt": self.redaction_excerpt,
            "prev_hash": self.prev_hash,
        }
        canonical = json.dumps(body, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class HashChainAuditLog:
    """Append-only, hash-chained audit log on disk.

    Usage:
        log = HashChainAuditLog(Path("audit.jsonl"))
        entry = log.append(decision=...)   # writes one line
        ok, idx = log.verify_chain()        # validates integrity
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Cache the last hash for O(1) append. On init, we read the file
        # tail; on a fresh file this is the genesis hash.
        self._last_hash = self._read_tail_hash()

    def append(
        self,
        *,
        decision_verdict: str,
        findings: list[dict[str, Any]],
        response_in: str,
        response_out: str,
        max_excerpt_chars: int = 240,
    ) -> AuditEntry:
        """Append one decision to the log. Returns the written AuditEntry."""
        entry = AuditEntry(
            entry_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            decision_verdict=decision_verdict,
            findings=findings,
            response_excerpt=response_in[:max_excerpt_chars],
            redaction_excerpt=response_out[:max_excerpt_chars],
            prev_hash=self._last_hash,
        )
        entry.hash = entry.compute_hash()
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
        self._last_hash = entry.hash
        return entry

    def entries(self) -> Iterator[AuditEntry]:
        """Iterate every entry in the log, in append order."""
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                raw = json.loads(line)
                yield AuditEntry(**raw)

    def verify_chain(self) -> tuple[bool, int | None, str]:
        """Walk the log and verify every entry.

        Returns (ok, broken_index, reason). On success: (True, None, "").
        On failure: (False, idx, reason) where idx is the 0-based index of
        the first entry whose chain integrity is broken.
        """
        prev = GENESIS_HASH
        for idx, entry in enumerate(self.entries()):
            if entry.prev_hash != prev:
                return (
                    False, idx,
                    f"prev_hash mismatch — expected {prev[:16]}..., "
                    f"got {entry.prev_hash[:16]}...",
                )
            recomputed = entry.compute_hash()
            if entry.hash != recomputed:
                return (
                    False, idx,
                    f"entry hash mismatch — content was modified after write",
                )
            prev = entry.hash
        return True, None, ""

    def __len__(self) -> int:
        if not self.path.exists():
            return 0
        with self.path.open("r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())

    # ------------------------------------------------------------------

    def _read_tail_hash(self) -> str:
        """Find the hash of the last entry, or GENESIS_HASH for a fresh log."""
        if not self.path.exists():
            return GENESIS_HASH
        last_hash = GENESIS_HASH
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    last_hash = obj.get("hash", GENESIS_HASH)
                except json.JSONDecodeError:
                    continue
        return last_hash


def verify_chain(path: Path | str) -> tuple[bool, int | None, str]:
    """Convenience: verify the chain of an existing log file."""
    return HashChainAuditLog(path).verify_chain()
