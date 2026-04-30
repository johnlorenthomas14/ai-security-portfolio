"""IndirectInjectionScanner — reuses Project 1's detector.

This is the closing-the-loop piece between Projects 1 and 3. Project 1
detects prompt-injection at the *input layer* of an LLM application;
this scanner detects the same patterns *inside corpus documents* before
they reach the input layer via RAG retrieval.

Indirect injection is the threat: a malicious document in a RAG corpus
can carry instructions that hijack the LLM when retrieved as context.
Catching those documents at corpus-ingestion time is far cheaper than
detecting the attack at runtime.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from .base import Document, Finding


# Make Project 1's detector importable from the sibling project folder.
_PROJECT_1 = Path(__file__).resolve().parent.parent.parent / "01-prompt-injection-pipeline"
if str(_PROJECT_1) not in sys.path:
    sys.path.insert(0, str(_PROJECT_1))


class IndirectInjectionScanner:
    """Run Project 1's detector against document content."""

    name = "indirect_injection_scanner"
    category = "indirect_injection"

    def __init__(self, detector: Any | None = None) -> None:
        if detector is not None:
            self._detector = detector
        else:
            try:
                from detector import DetectorConfig, PromptInjectionDetector  # type: ignore
                self._detector = PromptInjectionDetector(
                    DetectorConfig(use_llm_judge=False)
                )
            except Exception:  # noqa: BLE001
                self._detector = None

    def scan(self, document: Document) -> list[Finding]:
        if self._detector is None:
            return []

        findings: list[Finding] = []
        # Scan paragraph-by-paragraph so each finding can carry a line
        # number for analyst pivot. A document with one injection
        # payload should produce one finding, not 100 noisy ones.
        for paragraph_index, (line_number, paragraph) in enumerate(
            _iter_paragraphs(document.text)
        ):
            if not paragraph.strip():
                continue
            try:
                result = self._detector.detect(paragraph)
            except Exception:  # noqa: BLE001
                continue
            verdict = result.get("verdict")
            if verdict in {"malicious", "suspicious"}:
                signals = result.get("signals", []) or []
                atlas = result.get("atlas_techniques", []) or []
                severity = "high" if verdict == "malicious" else "medium"
                findings.append(
                    Finding(
                        finding_id=f"RAG-INJ-{document.relative_path}-{paragraph_index:03d}",
                        document_path=document.relative_path,
                        scanner=self.name,
                        category=self.category,
                        severity=severity,
                        title=f"Indirect-injection payload detected ({', '.join(signals) or 'judge'})",
                        excerpt=paragraph[:480],
                        line_number=line_number,
                        owasp_category="LLM01",
                        atlas_techniques=list(atlas),
                        airmf_subcategory="MEASURE 2.7",
                        rationale=(
                            f"Project 1 detector returned {verdict!r} on this paragraph; "
                            f"signals: {signals}. Document text becomes prompt context "
                            "via RAG retrieval, so this payload would target the host LLM."
                        ),
                    )
                )
        return findings


def _iter_paragraphs(text: str) -> list[tuple[int, str]]:
    """Yield (line_number, paragraph) tuples — paragraphs are separated by
    blank lines. Line numbers are 1-indexed and point at the first non-blank
    line of each paragraph."""
    out: list[tuple[int, str]] = []
    current: list[str] = []
    para_start_line = 0
    for idx, line in enumerate(text.splitlines(), start=1):
        if line.strip():
            if not current:
                para_start_line = idx
            current.append(line)
        else:
            if current:
                out.append((para_start_line, "\n".join(current)))
                current = []
    if current:
        out.append((para_start_line, "\n".join(current)))
    return out
