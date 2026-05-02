"""Scanner protocol + Finding / ModelArtifact dataclasses."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Protocol


@dataclass
class ModelArtifact:
    """One model directory under inspection."""

    root: Path

    def files(self) -> Iterator[Path]:
        """Yield every file in the model directory (recursive)."""
        if not self.root.exists():
            return
        for path in sorted(self.root.rglob("*")):
            if path.is_file():
                yield path

    def relative(self, path: Path) -> str:
        return str(path.relative_to(self.root))

    @staticmethod
    def sha256(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()


@dataclass
class Finding:
    """One scanner finding against one artifact."""

    finding_id: str
    artifact_path: str
    scanner: str
    category: str
    severity: str         # low | medium | high | critical
    title: str
    rationale: str
    matched_evidence: str = ""        # opcode trace, line excerpt, etc.
    line_number: int | None = None
    owasp_category: str = "LLM03"
    atlas_techniques: list[str] = field(default_factory=lambda: ["AML.T0010"])
    airmf_subcategory: str = "MAP 4.1"


class Scanner(Protocol):
    """Each scanner reads one ModelArtifact and returns findings."""

    name: str
    category: str

    def scan(self, artifact: ModelArtifact) -> list[Finding]:
        ...
