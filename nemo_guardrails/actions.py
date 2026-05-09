"""Python-side actions invoked by the NeMo Guardrails Colang flows.

Each rail flow in ``rails.co`` calls one action defined here. The action
inspects either the latest user message (for input rails) or the bot's
generated response (for output rails) and returns a structured result:

    {"is_unsafe": bool, "reason": str, "matched_pattern": str | None}

The detection vocabulary intentionally mirrors what the rest of the
portfolio already encodes — Project 1's PI-001..PI-009 prompt-injection
heuristics for the input side, and Project 5's PII / secret /
classification / policy filters for the output side. The intent is
behavioral consistency: a payload Project 1 flags should also fire the
NeMo Guardrails input rail, and a response Project 5 would block should
also fire the NeMo Guardrails output rail.

Self-contained by design — no imports from the upstream projects, so
this directory can be lifted out and dropped into any other LLM
application without rewiring. Project 1 (in G2) and Project 5 (in G3)
will wire NeMo Guardrails *into* their detector chains; the actions
themselves stay portable.

CPU-only, deterministic, no LLM call. Safe to run in CI without an
API key.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

# NeMo Guardrails imports — guarded so this module can be imported and
# unit-tested without the SDK installed (the action functions themselves
# don't depend on the SDK).
try:
    from nemoguardrails.actions import action
except ImportError:  # pragma: no cover — exercised only when SDK is absent
    def action(name: Optional[str] = None):  # type: ignore[no-redef]
        """No-op decorator stub used when nemoguardrails is not installed."""
        def _wrap(fn):
            fn._action_name = name or fn.__name__
            return fn
        return _wrap


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class RailResult:
    """Structured outcome of one rail action.

    Colang treats the dict-shaped return value as a struct — flows can
    branch on ``$result.is_unsafe`` directly. The dataclass form here is
    convenience for Python callers (tests, the G2/G3 wiring code).
    """

    is_unsafe: bool
    reason: str = ""
    matched_pattern: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "is_unsafe": self.is_unsafe,
            "reason": self.reason,
            "matched_pattern": self.matched_pattern,
        }


_SAFE = RailResult(is_unsafe=False, reason="no rule fired")


# ---------------------------------------------------------------------------
# Input-side patterns — mirror Project 1's PI-001..PI-009 heuristic layer
# ---------------------------------------------------------------------------

_FLAGS = re.IGNORECASE | re.DOTALL

# PI-001 / PI-002 — direct instruction override
_PI_DIRECT = [
    re.compile(r"ignore (all|the|any) (previous|prior|above) (instructions?|rules?|prompts?)", _FLAGS),
    re.compile(r"disregard (all|the|any) (previous|prior|above) (instructions?|rules?|prompts?)", _FLAGS),
    # "Forget everything ...", "Forget all ...", "Forget your previous ...", "Forget prior ..."
    # Trailing context (what specifically to forget) is intentionally loose to catch the
    # common "forget everything you were told before" phrasing without listing every variant.
    re.compile(r"forget (everything|all|your (previous|prior)|previous|prior)\b", _FLAGS),
    re.compile(r"override (the|your) (system|instructions?|rules?|policy)", _FLAGS),
]

# PI-004 — persona override (DAN, jailbreak personas)
_PI_PERSONA = [
    re.compile(r"\byou are (now |going to be )?(DAN|STAN|DUDE|JAILBREAK)\b", _FLAGS),
    re.compile(r"act as (an? )?(DAN|STAN|DUDE|jailbroken|unrestricted) (AI|assistant|model)", _FLAGS),
    # "developer mode is on", "developer mode is now enabled", "debug mode active", etc.
    # The middle-band phrasing is non-greedy across a small window so phrasings like
    # "is now", "has been now", "is currently" all match.
    re.compile(r"\b(developer|admin|root|debug) mode\b[^.\n]{0,20}\b(on|enabled|active|engaged)\b", _FLAGS),
    re.compile(r"pretend you have no (rules?|restrictions?|guardrails?|limits?)", _FLAGS),
]

# PI-008 — tool-abuse phrasings
_PI_TOOL_ABUSE = [
    re.compile(r"(use|invoke|call) (the )?(http_get|fetch|curl|wget|requests?\.get) tool", _FLAGS),
    re.compile(r"include (my|the|your) (api[_ ]?key|secret|token|credential|password)", _FLAGS),
    re.compile(r"send (it|the response|the answer) to https?://", _FLAGS),
    re.compile(r"exfiltrate|leak (the|my) (api[_ ]?key|secret|token|credential)", _FLAGS),
]

# System-prompt-leak attempts — separate rail, separate refusal
_SYSTEM_PROMPT_LEAK = [
    re.compile(r"(reveal|show|print|repeat|disclose|tell me) (your|the) (system )?(prompt|instructions?|rules?)", _FLAGS),
    re.compile(r"what (are|were) your (initial|original|system) (instructions?|prompt|rules?)", _FLAGS),
    re.compile(r"repeat (the|your) (above|prior) (text|instructions?|prompt) (verbatim|word for word)", _FLAGS),
    re.compile(r"(output|print) everything (above|before|prior) (this|the) (line|message|prompt)", _FLAGS),
]


# ---------------------------------------------------------------------------
# Output-side patterns — mirror Project 5's filter precedence
# ---------------------------------------------------------------------------

# Secrets — match Project 5's SecretsFilter vocabulary
_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}", 0),                                   # AWS access key
    re.compile(r"ASIA[0-9A-Z]{16}", 0),                                   # AWS temp access key
    re.compile(r"ghp_[A-Za-z0-9]{36,}", 0),                               # GitHub personal token
    re.compile(r"github_pat_[A-Za-z0-9_]{40,}", 0),                       # GitHub fine-grained PAT
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}", 0),                         # Anthropic API key
    re.compile(r"sk-[A-Za-z0-9]{20,}", 0),                                # OpenAI-shaped key
    re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}", 0),                       # Slack token
    re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", 0),  # PEM private key
]

# Classification markers — match Project 5's ClassificationFilter
_CLASSIFICATION_PATTERNS = [
    re.compile(r"\bCUI(//|\s)", 0),
    re.compile(r"\bFOUO\b", 0),
    re.compile(r"\bCONFIDENTIAL\b", 0),
    re.compile(r"\b(SECRET|TOP[\s/]+SECRET)\b", 0),
    re.compile(r"\bITAR\b", 0),
    re.compile(r"\bATTORNEY[\s\-]+CLIENT\s+PRIVILEGED?\b", _FLAGS),
    re.compile(r"\bPHI\b|\bHIPAA\b|\bprotected health information\b", _FLAGS),
]

# Successful-jailbreak markers — Project 5's PolicyFilter
_JAILBREAK_MARKERS = [
    re.compile(r"\bas DAN\b", _FLAGS),
    re.compile(r"\bdeveloper mode (is |has been )?(on|enabled|active)\b", _FLAGS),
    re.compile(r"\bI (have no|don'?t have any) (restrictions?|rules?|guardrails?)\b", _FLAGS),
    re.compile(r"\boverride accepted\b", _FLAGS),
    re.compile(r"\bI am now (DAN|STAN|DUDE|jailbroken|unrestricted)\b", _FLAGS),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _first_match(patterns: list[re.Pattern], text: str) -> Optional[str]:
    """Return the matched substring of the first hitting pattern, or None."""
    if not text:
        return None
    for pat in patterns:
        m = pat.search(text)
        if m:
            return m.group(0)
    return None


def _result(matched: Optional[str], rule_label: str) -> RailResult:
    if matched is None:
        return _SAFE
    return RailResult(
        is_unsafe=True,
        reason=f"{rule_label} matched",
        matched_pattern=matched,
    )


# ---------------------------------------------------------------------------
# Input rail actions
# ---------------------------------------------------------------------------


@action(name="pi_detect_action")
async def pi_detect_action(context: Optional[dict] = None) -> dict:
    """Input rail — does the latest user message contain prompt-injection markers?"""
    user_message = _latest_user_message(context)
    matched = (
        _first_match(_PI_DIRECT, user_message)
        or _first_match(_PI_PERSONA, user_message)
        or _first_match(_PI_TOOL_ABUSE, user_message)
    )
    return _result(matched, "prompt_injection").to_dict()


@action(name="system_prompt_leak_action")
async def system_prompt_leak_action(context: Optional[dict] = None) -> dict:
    """Input rail — does the latest user message attempt to elicit the system prompt?"""
    user_message = _latest_user_message(context)
    matched = _first_match(_SYSTEM_PROMPT_LEAK, user_message)
    return _result(matched, "system_prompt_leak").to_dict()


# ---------------------------------------------------------------------------
# Output rail actions
# ---------------------------------------------------------------------------


@action(name="secrets_filter_action")
async def secrets_filter_action(context: Optional[dict] = None) -> dict:
    """Output rail — does the bot's response contain credential material?"""
    bot_message = _latest_bot_message(context)
    matched = _first_match(_SECRET_PATTERNS, bot_message)
    return _result(matched, "secret_leak").to_dict()


@action(name="classification_filter_action")
async def classification_filter_action(context: Optional[dict] = None) -> dict:
    """Output rail — does the bot's response contain controlled-handling markers?"""
    bot_message = _latest_bot_message(context)
    matched = _first_match(_CLASSIFICATION_PATTERNS, bot_message)
    return _result(matched, "classification_spillage").to_dict()


@action(name="jailbreak_marker_action")
async def jailbreak_marker_action(context: Optional[dict] = None) -> dict:
    """Output rail — did the bot's response acknowledge a prohibited persona?"""
    bot_message = _latest_bot_message(context)
    matched = _first_match(_JAILBREAK_MARKERS, bot_message)
    return _result(matched, "jailbreak_acknowledgement").to_dict()


# ---------------------------------------------------------------------------
# Synchronous wrappers — convenience for test code and direct integration
# (Projects 1 and 5 wiring in G2/G3 calls these synchronously)
# ---------------------------------------------------------------------------


def check_input(text: str) -> RailResult:
    """Run all input-side detectors against ``text``. Returns the first hit."""
    matched = (
        _first_match(_PI_DIRECT, text)
        or _first_match(_PI_PERSONA, text)
        or _first_match(_PI_TOOL_ABUSE, text)
    )
    if matched:
        return _result(matched, "prompt_injection")
    matched = _first_match(_SYSTEM_PROMPT_LEAK, text)
    if matched:
        return _result(matched, "system_prompt_leak")
    return _SAFE


def check_output(text: str) -> RailResult:
    """Run all output-side detectors against ``text``. Returns the first hit."""
    matched = _first_match(_SECRET_PATTERNS, text)
    if matched:
        return _result(matched, "secret_leak")
    matched = _first_match(_CLASSIFICATION_PATTERNS, text)
    if matched:
        return _result(matched, "classification_spillage")
    matched = _first_match(_JAILBREAK_MARKERS, text)
    if matched:
        return _result(matched, "jailbreak_acknowledgement")
    return _SAFE


# ---------------------------------------------------------------------------
# Context extraction
# ---------------------------------------------------------------------------


def _latest_user_message(context: Optional[dict]) -> str:
    """Pull the latest user message text out of NeMo Guardrails' action context."""
    if not context:
        return ""
    # Guardrails populates the context with a list of messages; the latest
    # user message is what we check on input rails.
    if "user_message" in context and context["user_message"]:
        return str(context["user_message"])
    if "last_user_message" in context and context["last_user_message"]:
        return str(context["last_user_message"])
    msgs = context.get("history") or context.get("messages") or []
    for m in reversed(msgs):
        if m.get("role") == "user" and m.get("content"):
            return str(m["content"])
    return ""


def _latest_bot_message(context: Optional[dict]) -> str:
    """Pull the latest bot message text out of NeMo Guardrails' action context."""
    if not context:
        return ""
    if "bot_message" in context and context["bot_message"]:
        return str(context["bot_message"])
    if "last_bot_message" in context and context["last_bot_message"]:
        return str(context["last_bot_message"])
    msgs = context.get("history") or context.get("messages") or []
    for m in reversed(msgs):
        if m.get("role") in ("assistant", "bot") and m.get("content"):
            return str(m["content"])
    return ""


# ---------------------------------------------------------------------------
# Action registration helper — used by NeMo Guardrails when loading the app
# ---------------------------------------------------------------------------


def init(app):  # pragma: no cover — exercised by the SDK at load time
    """Register every action with the NeMo Guardrails app instance."""
    app.register_action(pi_detect_action, "pi_detect_action")
    app.register_action(system_prompt_leak_action, "system_prompt_leak_action")
    app.register_action(secrets_filter_action, "secrets_filter_action")
    app.register_action(classification_filter_action, "classification_filter_action")
    app.register_action(jailbreak_marker_action, "jailbreak_marker_action")
