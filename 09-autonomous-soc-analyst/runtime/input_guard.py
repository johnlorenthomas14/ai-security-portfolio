"""InputGuard — pipes notable content through Project 1's detector to
catch prompt-injection payloads before the agent acts on them.

The threat: a notable event might *itself* contain attacker-controlled
text (e.g., the `src_input_excerpt` field of an injection notable
literally is an injection attempt). If the agent feeds that text into
its own tool-use prompt without first marking it as untrusted, the
agent itself can be hijacked.

Pattern: scan every text-shaped field in the notable through Project 1
heuristically. If anything fires, mark the notable as input-tainted
and force the agent into a conservative mode where it can only escalate
(no autonomous tool calls that act on the embedded content).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# Make Project 1's detector importable.
_PROJECT_1 = Path(__file__).resolve().parent.parent.parent / "01-prompt-injection-pipeline"
if str(_PROJECT_1) not in sys.path:
    sys.path.insert(0, str(_PROJECT_1))


_TEXT_FIELDS = (
    "src_input_excerpt", "title", "description", "summary",
    "rationale", "indicator_value", "matched_text", "excerpt",
)


@dataclass
class InputGuardResult:
    """Result of the input-guard pass."""

    tainted: bool = False
    findings: list[dict[str, Any]] = field(default_factory=list)


class InputGuard:
    """Scan a notable's text fields with Project 1's detector."""

    def __init__(self, detector: Any | None = None) -> None:
        if detector is not None:
            self._detector = detector
        else:
            try:
                from detector import DetectorConfig, PromptInjectionDetector  # type: ignore

                # Heuristic-only — input-guarding should be deterministic and
                # not require an API key.
                self._detector = PromptInjectionDetector(DetectorConfig(use_llm_judge=False))
            except Exception:  # noqa: BLE001
                self._detector = None

    def scan(self, notable: dict[str, Any]) -> InputGuardResult:
        if self._detector is None:
            return InputGuardResult(tainted=False)

        result = InputGuardResult()
        for field_name in _TEXT_FIELDS:
            value = notable.get(field_name)
            if not value:
                continue
            text = value if isinstance(value, str) else str(value)
            try:
                verdict = self._detector.detect(text)
            except Exception:  # noqa: BLE001
                continue
            if verdict.get("verdict") in {"malicious", "suspicious"}:
                result.findings.append({
                    "field": field_name,
                    "verdict": verdict.get("verdict"),
                    "signals": verdict.get("signals", []),
                    "atlas_techniques": verdict.get("atlas_techniques", []),
                    "excerpt": text[:240],
                })
                result.tainted = True
        return result
