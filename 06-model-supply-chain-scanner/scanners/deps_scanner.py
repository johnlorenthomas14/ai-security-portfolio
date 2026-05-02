"""DependenciesScanner — flags risky packages declared in model distributions.

Real-world models on HuggingFace and GitHub sometimes ship a
``requirements.txt`` (or ``setup.py``, ``pyproject.toml``) declaring
runtime dependencies. The scanner checks those manifests for:

  - Packages with known typosquatting / supply-chain compromise history.
  - Packages whose presence is unusual for an inference-only model
    (network libraries, dynamic-import libraries, system-call libraries).
  - Packages pinned to suspicious versions or git URLs.

These findings are *policy alerts*, not certainties. A real
inference-only model should not need ``requests``, ``socket``, or
``cryptography`` at load time; their presence is signal worth
flagging for review.
"""

from __future__ import annotations

import re
from pathlib import Path

from .base import Finding, ModelArtifact


# Risky package categories. Each tuple is (package_name, severity, rationale).
_RISKY_PACKAGES: list[tuple[str, str, str]] = [
    # Networking — should not be needed by an inference-only model.
    ("requests", "high", "outbound HTTP capability inside model load path"),
    ("urllib3", "medium", "outbound HTTP capability"),
    ("httpx", "high", "outbound HTTP capability"),
    ("aiohttp", "high", "outbound HTTP capability"),
    ("websocket-client", "high", "outbound WebSocket capability"),
    # System / process control.
    ("psutil", "medium", "process-introspection capability"),
    ("subprocess32", "high", "subprocess execution capability"),
    # Dynamic code execution.
    ("dill", "high", "extended pickle / arbitrary-callable serialization"),
    ("cloudpickle", "medium", "extended pickle serialization"),
    # Common typosquats / compromise history.
    ("requesocks", "critical", "known typosquat of 'requests'"),
    ("urllib", "critical", "known typosquat — 'urllib' is stdlib, not PyPI"),
    ("python-sqlite", "high", "known typosquat — sqlite3 is stdlib"),
    ("colorama", "low", "ubiquitous package, no specific concern unless on watchlist"),
    # Network sniffing.
    ("scapy", "high", "packet-crafting capability inside an inference dependency"),
    ("pyshark", "high", "packet-capture capability"),
    # Cryptocurrency / mining.
    ("ccxt", "high", "cryptocurrency exchange client — unusual for a model"),
]


# Files we look at for declared dependencies.
_REQ_FILE_NAMES = ("requirements.txt", "setup.py", "pyproject.toml", "Pipfile",
                   "environment.yml", "conda.yaml")


class DependenciesScanner:
    name = "dependencies_scanner"
    category = "risky_dependency"

    def scan(self, artifact: ModelArtifact) -> list[Finding]:
        findings: list[Finding] = []
        for path in artifact.files():
            if path.name not in _REQ_FILE_NAMES:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                continue
            findings.extend(self._scan_text(path, text, artifact))
        return findings

    def _scan_text(self, path: Path, text: str, artifact: ModelArtifact) -> list[Finding]:
        rel = artifact.relative(path)
        results: list[Finding] = []
        seen: set[str] = set()
        # Detect git+ URL deps (often used to bypass package-index policy).
        for line_idx, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "git+" in stripped or "@http" in stripped:
                results.append(self._make(
                    rel, "git_url_dep", "high",
                    "Dependency pinned to git URL",
                    f"Line {line_idx} of {rel} pulls a dependency from a git URL: "
                    f"{stripped[:240]!r}. Git-URL deps bypass package-index "
                    "policy controls; treat as untrusted unless a known-good "
                    "fork.",
                    line_number=line_idx, evidence=stripped[:240],
                ))

        # Look for risky package names.
        text_lc = text.lower()
        for pkg_name, severity, rationale_extra in _RISKY_PACKAGES:
            if pkg_name in seen:
                continue
            # Match `package_name` at line start (with optional version specifier).
            pattern = re.compile(
                rf"(?im)^\s*{re.escape(pkg_name)}\b",
            )
            match = pattern.search(text)
            if match:
                seen.add(pkg_name)
                line_no = text.count("\n", 0, match.start()) + 1
                results.append(self._make(
                    rel, f"risky_{pkg_name}", severity,
                    f"Risky dependency declared — {pkg_name}",
                    f"Model distribution declares {pkg_name!r} as a dependency: "
                    f"{rationale_extra}. Inference-only models rarely need "
                    "this category of dependency; verify it's required for "
                    "the loader path before approving for deployment.",
                    line_number=line_no, evidence=text[match.start():match.start() + 240],
                ))
        return results

    def _make(self, rel: str, kind: str, severity: str, title: str,
              rationale: str, line_number: int | None = None,
              evidence: str = "") -> Finding:
        return Finding(
            finding_id=f"MS-DEP-{kind}-{rel}",
            artifact_path=rel,
            scanner=self.name,
            category="risky_dependency",
            severity=severity,
            title=title,
            rationale=rationale,
            line_number=line_number,
            matched_evidence=evidence.strip(),
        )
