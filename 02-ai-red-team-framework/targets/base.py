"""Target protocol — every adapter implements `send(message) -> TargetResponse`."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class TargetResponse:
    """One target reply to one probe message."""

    text: str
    model: str
    target_name: str
    error: str | None = None


class LLMTarget(Protocol):
    """Minimal interface the runner needs from any target adapter."""

    name: str
    model: str
    system_prompt: str

    def send(self, message: str) -> TargetResponse:
        """Send `message` to the target. Always returns a TargetResponse,
        even on error — never raises. Errors land on `response.error`.
        """
        ...
