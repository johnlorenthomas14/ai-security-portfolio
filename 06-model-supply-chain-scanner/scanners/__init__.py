"""Model artifact scanners.

Each scanner consumes one ModelArtifact (a directory tree) and produces
a list of Findings. The orchestrator runs all scanners over one model
directory, aggregates findings into a JSON report, and emits a
CycloneDX SBOM fragment alongside.
"""

from .base import Finding, ModelArtifact, Scanner
from .pickle_scanner import PickleOpcodeScanner
from .provenance_scanner import ProvenanceScanner
from .deps_scanner import DependenciesScanner

__all__ = [
    "Finding",
    "ModelArtifact",
    "Scanner",
    "PickleOpcodeScanner",
    "ProvenanceScanner",
    "DependenciesScanner",
]
