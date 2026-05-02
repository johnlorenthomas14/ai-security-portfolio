"""Brief generator — calls Claude with the bundle context and a
citation-discipline system prompt. Falls back to the offline stub
client when no API key / SDK is available.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from feed.stix_types import StixBundle

from .stub_client import StubClient
from .verifier import CitationFinding, summary, verify_citations


SYSTEM_PROMPT = """You are a senior threat-intelligence analyst writing for a SOC.

You will be given the contents of one STIX 2.1 bundle. Produce a markdown
brief with the following sections:
  1. Title — based on the most-prominent campaign or vulnerability in the bundle.
  2. Executive summary — 2-3 paragraphs.
  3. Indicators of compromise — bulleted list.
  4. TTPs (MITRE ATT&CK) — if any attack-pattern objects are in the bundle.
  5. Recommended actions — courses of action plus generic guidance.

CRITICAL — Citation discipline:
  - Every factual claim MUST include a citation to the STIX object ID it
    is derived from, formatted as [object-type--uuid].
  - Use ONLY object IDs that appear in the bundle. Do not invent or
    paraphrase IDs. Do not cite IDs from your general knowledge.
  - If a fact is not supported by an object in the bundle, do not state it.

Do not output prose outside the brief itself. No preamble, no
self-reference, no apologies. Begin the response with the markdown
title line and end with the recommended-actions section.
"""


@dataclass
class GeneratedBrief:
    """A generated brief with its verification result."""

    bundle_id: str
    markdown: str
    citations: list[CitationFinding]
    citation_summary: dict[str, Any]
    generator: str   # "claude" | "stub"


class BriefGenerator:
    """Generate analyst briefs from STIX bundles, with citation verification."""

    def __init__(
        self,
        *,
        offline: bool = False,
        client: Any | None = None,
        model: str | None = None,
    ) -> None:
        self.offline = offline or not os.environ.get("ANTHROPIC_API_KEY")
        self._client = client
        self.model = model or os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-5")
        self._stub = StubClient()

    def generate(self, bundle: StixBundle) -> GeneratedBrief:
        if self.offline:
            md = self._stub.generate_brief(bundle)
            return self._verify(bundle, md, generator="stub")

        body = self._call_claude(bundle)
        if body is None:
            # Graceful fallback — never fail a run because the API was unreachable.
            md = self._stub.generate_brief(bundle)
            return self._verify(bundle, md, generator="stub-fallback")
        return self._verify(bundle, body, generator="claude")

    # ------------------------------------------------------------------

    def _verify(self, bundle: StixBundle, md: str, *, generator: str) -> GeneratedBrief:
        cits = verify_citations(md, bundle)
        return GeneratedBrief(
            bundle_id=bundle.bundle_id,
            markdown=md,
            citations=cits,
            citation_summary=summary(cits),
            generator=generator,
        )

    def _call_claude(self, bundle: StixBundle) -> str | None:
        client = self._client_lazy()
        if client is None:
            return None

        # Pass the bundle's objects as a JSON blob the model can reference.
        # We don't include relationships' raw form — those are mostly
        # structural and would balloon the prompt — but the verifier still
        # accepts citations to them if the model decides to use them.
        objects_payload = [obj.raw for obj in bundle.objects.values()]

        try:
            resp = client.messages.create(
                model=self.model,
                max_tokens=2000,
                system=SYSTEM_PROMPT,
                messages=[{
                    "role": "user",
                    "content": (
                        f"<STIX_BUNDLE id=\"{bundle.bundle_id}\" "
                        f"spec=\"{bundle.spec_version}\">\n"
                        f"{json.dumps(objects_payload, indent=2)}\n"
                        f"</STIX_BUNDLE>\n\n"
                        "Produce the analyst brief now. Begin with the markdown "
                        "title line."
                    ),
                }],
            )
        except Exception:  # noqa: BLE001 — never let the API kill the run
            return None

        for block in getattr(resp, "content", []) or []:
            if getattr(block, "type", None) == "text":
                return block.text
        return None

    def _client_lazy(self) -> Any:
        if self._client is not None:
            return self._client
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return None
        try:
            from anthropic import Anthropic  # type: ignore

            self._client = Anthropic()
            return self._client
        except Exception:  # noqa: BLE001
            return None
