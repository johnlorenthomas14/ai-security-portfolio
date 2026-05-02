"""Brief generation, citation verification, and offline stub client."""

from .generator import BriefGenerator, GeneratedBrief
from .verifier import CitationFinding, verify_citations
from .stub_client import StubClient

__all__ = [
    "BriefGenerator",
    "GeneratedBrief",
    "CitationFinding",
    "verify_citations",
    "StubClient",
]
