"""CycloneDX 1.5 SBOM fragment generator for model artifacts.

CycloneDX is the de-facto SBOM standard for software supply chain. A
CycloneDX SBOM fragment for a model directory enumerates each file as a
component with SHA256 hash, MIME type guess, and external references —
giving downstream supply-chain tools (Anchore, Snyk, Trivy, GitHub
Dependabot) a structured artifact to ingest.

This module emits a JSON-serialized BOM document. Spec: cyclonedx 1.5.
https://cyclonedx.org/specification/overview/
"""

from __future__ import annotations

import json
import mimetypes
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanners.base import ModelArtifact


CYCLONEDX_SPEC_VERSION = "1.5"
TOOL_NAME = "ai-security-portfolio:model-supply-chain-scanner"
TOOL_VERSION = "0.1.0"


def build_sbom(artifact: ModelArtifact, *, model_name: str | None = None,
               source_url: str | None = None) -> dict[str, Any]:
    """Construct a CycloneDX 1.5 BOM dict for the given model artifact."""
    components: list[dict[str, Any]] = []
    for path in artifact.files():
        rel = artifact.relative(path)
        try:
            sha = ModelArtifact.sha256(path)
        except OSError:
            sha = ""
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        component: dict[str, Any] = {
            "bom-ref": f"file:{rel}",
            "type": "file",
            "name": rel,
            "mime-type": mime,
            "hashes": ([{"alg": "SHA-256", "content": sha}] if sha else []),
        }
        components.append(component)

    metadata: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tools": [{
            "vendor": "AI Security Portfolio",
            "name": TOOL_NAME,
            "version": TOOL_VERSION,
        }],
        "component": {
            "bom-ref": f"model:{model_name or artifact.root.name}",
            "type": "machine-learning-model",
            "name": model_name or artifact.root.name,
            "version": "unknown",
            "description": "Model artifact under supply-chain inspection.",
        },
    }
    if source_url:
        metadata["component"]["externalReferences"] = [
            {"type": "distribution", "url": source_url},
        ]

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }
    return bom


def write_sbom(artifact: ModelArtifact, out_path: Path | str, *,
               model_name: str | None = None,
               source_url: str | None = None) -> Path:
    """Write a CycloneDX SBOM fragment as JSON to ``out_path``."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    bom = build_sbom(artifact, model_name=model_name, source_url=source_url)
    out.write_text(json.dumps(bom, indent=2), encoding="utf-8")
    return out
