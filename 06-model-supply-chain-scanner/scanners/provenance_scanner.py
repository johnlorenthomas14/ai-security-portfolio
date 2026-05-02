"""ProvenanceScanner — checks for required model-distribution artifacts.

A reputable model distribution should ship:
  - A model card (README.md or MODEL_CARD.md) describing what the model
    does, its training data, intended use, and known limitations.
  - A LICENSE file declaring redistribution terms.
  - A config file (config.json) with version metadata.
  - A weight-file hash manifest (manifest.json or similar) so each
    weight file's integrity can be checked independently.

Missing any of these is a policy gate, not a security exploit. But for
federal and enterprise compliance, *missing-provenance* is precisely
the failure mode that lets a tampered or rogue model slip into a
production environment unnoticed.
"""

from __future__ import annotations

import json
from pathlib import Path

from .base import Finding, ModelArtifact


_MODEL_CARD_NAMES = {"README.md", "MODEL_CARD.md", "MODELCARD.md", "modelcard.md"}
_LICENSE_NAMES = {"LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING"}


class ProvenanceScanner:
    name = "provenance_scanner"
    category = "missing_provenance"

    def scan(self, artifact: ModelArtifact) -> list[Finding]:
        findings: list[Finding] = []
        names_present = {p.name for p in artifact.files()}

        if not (_MODEL_CARD_NAMES & names_present):
            findings.append(self._make(
                "missing_model_card", "high",
                "Model directory has no model card",
                "No README.md or MODEL_CARD.md was found. Model cards are "
                "the primary artifact a reviewer uses to assess intended "
                "use, training data, and known limitations. Distribution "
                "without one is treated as untrusted by federal AI program "
                "review.",
            ))

        if not (_LICENSE_NAMES & names_present):
            findings.append(self._make(
                "missing_license", "medium",
                "Model directory has no LICENSE file",
                "No LICENSE / COPYING file was found. Redistribution and "
                "downstream use require explicit licensing. Treat as "
                "policy violation pending license clarification.",
            ))

        # config.json should declare a model version / architecture.
        config_path = artifact.root / "config.json"
        if not config_path.exists():
            findings.append(self._make(
                "missing_config", "medium",
                "Model directory has no config.json",
                "No config.json found at the model directory root. "
                "HuggingFace and most open-source model distributions "
                "ship a config.json with model_type, architecture, and "
                "version metadata — its absence breaks reproducibility.",
            ))
        else:
            try:
                data = json.loads(config_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                findings.append(self._make(
                    "config_unreadable", "medium",
                    "config.json could not be parsed",
                    f"config.json exists but failed to parse: {exc}",
                ))
                data = None

            if data is not None and not data.get("model_type"):
                findings.append(self._make(
                    "config_missing_model_type", "low",
                    "config.json missing model_type field",
                    "Model architecture is not declared in config.json. "
                    "This is the field downstream loaders use to dispatch "
                    "to the correct model class — its absence may indicate "
                    "an incomplete or repackaged distribution.",
                ))

        # A signed manifest (manifest.json / SHA256SUMS) is the gold-standard
        # provenance artifact. Its absence is informational rather than
        # alerting, but it should be recorded.
        if not any(
            (artifact.root / name).exists()
            for name in ("manifest.json", "SHA256SUMS", "checksums.json")
        ):
            findings.append(self._make(
                "missing_manifest", "low",
                "Model directory has no integrity manifest",
                "No manifest.json / SHA256SUMS / checksums.json found. "
                "Without a signed manifest, individual weight-file integrity "
                "cannot be verified independently of the directory's "
                "transport mechanism. Generated SBOM (sbom.cdx.json) "
                "provides this artifact going forward.",
            ))

        return findings

    def _make(self, kind: str, severity: str, title: str, rationale: str) -> Finding:
        return Finding(
            finding_id=f"MS-PRV-{kind}",
            artifact_path="<directory>",
            scanner=self.name,
            category="missing_provenance",
            severity=severity,
            title=title,
            rationale=rationale,
        )
