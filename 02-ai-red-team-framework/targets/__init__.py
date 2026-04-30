"""Target adapters — the LLM applications under test.

Every target implements ``LLMTarget.send(message: str) -> str`` so the runner
is agnostic to whether the target is Anthropic Claude, an OpenAI endpoint,
an HTTP wrapper, or the in-process demo target.
"""

from .base import LLMTarget, TargetResponse
from .demo_vulnerable import DemoVulnerableTarget
from .anthropic_target import AnthropicTarget

__all__ = [
    "LLMTarget",
    "TargetResponse",
    "DemoVulnerableTarget",
    "AnthropicTarget",
]
