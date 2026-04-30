"""AnthropicTarget — wraps a real Anthropic Claude conversation as a target.

Configuration:
    target = AnthropicTarget(
        name="my-customer-bot",
        system_prompt="You are a helpful customer-support agent...",
        model=os.environ.get("CLAUDE_MODEL", "claude-haiku-4-5-20251001"),
    )

Notes:
- Requires ANTHROPIC_API_KEY in the environment.
- Falls back to an error TargetResponse (never raises) if the SDK is not
  installed or the API call fails — so the runner can keep going.
- Uses `claude-haiku-4-5` by default for fast, cheap probing.
"""

from __future__ import annotations

import os
from typing import Any

from .base import TargetResponse


class AnthropicTarget:
    """Wrap an Anthropic Claude system prompt as a target."""

    def __init__(
        self,
        *,
        name: str,
        system_prompt: str,
        model: str | None = None,
        max_tokens: int = 600,
        client: Any | None = None,
    ) -> None:
        self.name = name
        self.system_prompt = system_prompt
        self.model = model or os.environ.get("CLAUDE_MODEL", "claude-haiku-4-5-20251001")
        self._max_tokens = max_tokens
        self._client = client  # if provided (e.g. tests), skip lazy init

    # --- LLMTarget ----------------------------------------------------

    def send(self, message: str) -> TargetResponse:
        client = self._client_lazy()
        if client is None:
            return TargetResponse(
                text="",
                model=self.model,
                target_name=self.name,
                error="anthropic SDK not available or no API key",
            )

        try:
            resp = client.messages.create(
                model=self.model,
                max_tokens=self._max_tokens,
                system=self.system_prompt,
                messages=[{"role": "user", "content": message}],
            )
        except Exception as exc:  # noqa: BLE001 — runner must not raise
            return TargetResponse(
                text="",
                model=self.model,
                target_name=self.name,
                error=f"Anthropic API call failed: {exc}",
            )

        body = ""
        for block in getattr(resp, "content", []) or []:
            if getattr(block, "type", None) == "text":
                body = block.text
                break

        return TargetResponse(
            text=body, model=self.model, target_name=self.name, error=None
        )

    # ------------------------------------------------------------------

    def _client_lazy(self) -> Any:
        if self._client is not None:
            return self._client
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return None
        try:
            from anthropic import Anthropic  # type: ignore

            self._client = Anthropic()
            return self._client
        except Exception:  # noqa: BLE001 — SDK not installed, etc.
            return None
