"""Tool protocol + ToolCall / ToolResult dataclasses.

Tools are plain Python objects that expose a uniform interface:

    name           — short identifier ("splunk_search")
    description    — one-line description for the LLM's tool-use prompt
    parameters     — JSON-schema-shaped param list for tool selection
    invoke(args)   — actual callable; returns dict of result data

The agent's tool-use loop never executes Python from the LLM directly.
The LLM picks a tool name + a parameters dict; the agent dispatches to
the matching Tool object. This keeps the trust boundary clean.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class ToolCall:
    """One LLM-requested tool invocation."""

    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResult:
    """Result returned from a tool invocation. `error` is non-None on
    any failure path; tools never raise."""

    tool_name: str
    arguments: dict[str, Any]
    output: dict[str, Any]
    error: str | None = None


class Tool(Protocol):
    """Each tool implements name, description, parameters, and invoke."""

    name: str
    description: str
    parameters: dict[str, Any]   # JSON-schema-style

    def invoke(self, arguments: dict[str, Any]) -> dict[str, Any]:
        ...


# ---------------------------------------------------------------------------
# Tiny registry helper — used by stub LLM client to dispatch by tool name.
# ---------------------------------------------------------------------------


def registry(tools: list[Tool]) -> dict[str, Tool]:
    return {t.name: t for t in tools}
