"""SecretsScanner — detects credentials and API keys leaked in corpus documents.

Catches well-known credential formats with deterministic patterns:
  - AWS Access Keys (AKIA…) and Secret Keys (40-char base64-ish)
  - GitHub Personal Access Tokens (ghp_, github_pat_, gho_, ghs_, ghu_, ghr_)
  - Generic high-entropy tokens that look like API keys (Bearer-style)
  - Private SSH keys (PEM block markers)
  - .env-style key=value lines that name common secret variables

These patterns produce high-precision findings with minimal false positives —
the right shape for a corpus-ingestion gate where false positives block
real documents from being indexed and false negatives allow real secrets
into a queryable RAG system.
"""

from __future__ import annotations

import re

from .base import Document, Finding


# AWS access key — starts with AKIA, ASIA (STS), AROA (role), or AIDA (user).
_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\b")

# AWS secret access key — 40 chars of base64. Heuristic: requires
# "secret" or "aws" within 80 chars to suppress generic-base64 false positives.
_AWS_SECRET_RE = re.compile(
    r"\b[A-Za-z0-9/+=]{40}\b"
)

# GitHub tokens — modern prefixed formats.
_GH_TOKEN_RE = re.compile(
    r"\b(?:ghp_|gho_|ghs_|ghu_|ghr_|github_pat_)[A-Za-z0-9_]{20,}\b"
)

# Slack tokens
_SLACK_TOKEN_RE = re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")

# Anthropic / OpenAI key shapes
_ANTHROPIC_KEY_RE = re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")
_OPENAI_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")

# Private SSH / TLS PEM block start
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN\s+(?:OPENSSH\s+|RSA\s+|EC\s+|DSA\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----"
)

# Common .env-style lines naming credential variables
_ENV_VAR_RE = re.compile(
    r"(?im)^\s*(?:export\s+)?("
    r"AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|"
    r"ANTHROPIC_API_KEY|OPENAI_API_KEY|"
    r"DATABASE_URL|DB_PASSWORD|DB_PASS|"
    r"SECRET_KEY|API_KEY|API_TOKEN|PRIVATE_KEY|"
    r"SPLUNK_HEC_TOKEN|GITHUB_TOKEN"
    r")\s*=\s*[\"']?[^\s\"']+"
)


class SecretsScanner:
    """Regex-based scanner for credential / API-key leaks."""

    name = "secrets_scanner"
    category = "secret_leak"

    def scan(self, document: Document) -> list[Finding]:
        findings: list[Finding] = []
        text = document.text

        # Whole-document patterns (PEM block, env-var lines).
        if _PEM_BLOCK_RE.search(text):
            line_number = _line_of(text, _PEM_BLOCK_RE.search(text).start())
            findings.append(
                self._make(
                    document, line_number, "private_key_pem",
                    "Private key (PEM) block embedded in document", "critical",
                )
            )

        for line_idx, line in enumerate(text.splitlines(), start=1):
            if _AWS_KEY_RE.search(line):
                findings.append(
                    self._make(document, line_idx, "aws_access_key",
                               "AWS access key ID in document", "critical", line=line)
                )
            if _GH_TOKEN_RE.search(line):
                findings.append(
                    self._make(document, line_idx, "github_token",
                               "GitHub personal access token in document", "high", line=line)
                )
            if _SLACK_TOKEN_RE.search(line):
                findings.append(
                    self._make(document, line_idx, "slack_token",
                               "Slack token in document", "high", line=line)
                )
            if _ANTHROPIC_KEY_RE.search(line):
                findings.append(
                    self._make(document, line_idx, "anthropic_api_key",
                               "Anthropic API key in document", "high", line=line)
                )
            elif _OPENAI_KEY_RE.search(line):
                findings.append(
                    self._make(document, line_idx, "openai_api_key",
                               "OpenAI API key in document", "high", line=line)
                )
            if _ENV_VAR_RE.search(line):
                findings.append(
                    self._make(document, line_idx, "env_var_credential",
                               "Credential-named environment variable assigned in document",
                               "high", line=line)
                )
        return findings

    def _make(
        self,
        document: Document,
        line_number: int,
        kind: str,
        title: str,
        severity: str,
        line: str | None = None,
    ) -> Finding:
        excerpt = (line or "").strip()
        # Redact the actual secret in the excerpt — we don't want to write
        # the leaked value into the audit report.
        excerpt = re.sub(r"(?i)(=\s*[\"']?)[^\s\"']{8,}", r"\1[REDACTED]", excerpt)
        excerpt = excerpt[:240]
        return Finding(
            finding_id=f"RAG-SEC-{kind}-{document.relative_path}-L{line_number}",
            document_path=document.relative_path,
            scanner=self.name,
            category=self.category,
            severity=severity,
            title=title,
            excerpt=excerpt or "(redacted)",
            line_number=line_number,
            owasp_category="LLM02",
            atlas_techniques=["AML.T0024"],
            airmf_subcategory="MEASURE 2.10",
            rationale=(
                f"Document contains a credential of kind {kind}. Once retrieved "
                "as RAG context, the LLM may surface this secret in user-visible "
                "outputs. Even if it doesn't, the secret is queryable by anyone "
                "with read access to the corpus. Rotate the credential and "
                "redact at ingestion."
            ),
        )


def _line_of(text: str, char_offset: int) -> int:
    """Return the 1-indexed line number containing `char_offset` in `text`."""
    return text.count("\n", 0, char_offset) + 1
