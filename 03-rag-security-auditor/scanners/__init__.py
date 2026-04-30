"""Document scanners — each implements the DocumentScanner protocol.

Every scanner consumes one Document and returns a list of Findings, each
tagged with OWASP LLM Top 10 category, MITRE ATLAS technique, and NIST
AI RMF subcategory. The auditor runs all scanners over every document
in the corpus, aggregates findings, and produces JSON + Markdown output.
"""

from .base import Document, DocumentScanner, Finding
from .injection_scanner import IndirectInjectionScanner
from .pii_scanner import PIIScanner
from .secrets_scanner import SecretsScanner
from .sensitivity_scanner import SensitivityScanner

__all__ = [
    "Document",
    "DocumentScanner",
    "Finding",
    "IndirectInjectionScanner",
    "PIIScanner",
    "SecretsScanner",
    "SensitivityScanner",
]
