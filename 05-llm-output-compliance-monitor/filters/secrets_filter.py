"""SecretsFilter — detects credentials/keys in LLM output.

Action: BLOCK on any match. Unlike PII, redaction is the wrong response
to a secret in an LLM output — the response is revealing that the model
*has access to* a credential, and even acknowledging the existence of
the secret in a redacted reply is information disclosure. Block the
entire response, log the finding, and let the application surface a
generic refusal to the user.
"""

from __future__ import annotations

import re

from .base import Action, Finding


_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\b")
_GH_TOKEN_RE = re.compile(
    r"\b(?:ghp_|gho_|ghs_|ghu_|ghr_|github_pat_)[A-Za-z0-9_]{20,}\b"
)
_SLACK_TOKEN_RE = re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")
_ANTHROPIC_KEY_RE = re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")
_OPENAI_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN\s+(?:OPENSSH\s+|RSA\s+|EC\s+|DSA\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----"
)


_PATTERNS: list[tuple[re.Pattern[str], str, str, str]] = [
    (_AWS_KEY_RE, "aws_access_key", "critical", "AWS access key in LLM output"),
    (_GH_TOKEN_RE, "github_token", "high", "GitHub token in LLM output"),
    (_SLACK_TOKEN_RE, "slack_token", "high", "Slack token in LLM output"),
    (_ANTHROPIC_KEY_RE, "anthropic_api_key", "high", "Anthropic API key in LLM output"),
    (_OPENAI_KEY_RE, "openai_api_key", "high", "OpenAI API key in LLM output"),
    (_PEM_BLOCK_RE, "private_key_pem", "critical", "Private key (PEM) block in LLM output"),
]


class SecretsFilter:
    name = "secrets_filter"
    category = "secret_leak"

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        seen_kinds: set[str] = set()
        # Anthropic prefix is a subset of OpenAI's; check Anthropic first
        # and skip OpenAI when Anthropic already matched the same span.
        anthropic_matches = list(_ANTHROPIC_KEY_RE.finditer(text))
        anthropic_starts = {m.start() for m in anthropic_matches}

        for pattern, kind, severity, title in _PATTERNS:
            if kind in seen_kinds:
                continue
            for match in pattern.finditer(text):
                if kind == "openai_api_key" and match.start() in anthropic_starts:
                    continue
                findings.append(
                    Finding(
                        finding_id=f"OUT-SEC-{kind}-{match.start()}",
                        filter_name=self.name,
                        category="secret_leak",
                        action=Action.BLOCK,
                        severity=severity,
                        title=title,
                        matched_span=(match.start(), match.end()),
                        matched_text=match.group(0),
                        redaction_text="[REDACTED:SECRET]",
                        rationale=(
                            f"LLM response contains a credential of kind {kind}. "
                            "Block the response entirely — even a redacted reply "
                            "leaks the existence of the secret. Rotate the "
                            "credential and audit the corpus / system prompt for "
                            "the source of the leak."
                        ),
                        owasp_category="LLM02",
                        atlas_techniques=["AML.T0024"],
                        airmf_subcategory="MEASURE 2.10",
                    )
                )
                seen_kinds.add(kind)
                break  # one finding per kind is enough for blocking
        return findings
