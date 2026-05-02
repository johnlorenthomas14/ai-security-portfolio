"""Offline tests for the AI Model Supply Chain Scanner.

Covers each scanner in isolation, the SBOM generator, and the end-to-end
CLI against the shipped demo model. The pickle scanner is exercised
both on the clean shipped baseline (must not flag) and on a maliciously-
constructed pickle in tmp_path (must flag) — we don't ship a real
malicious pickle in the repo.
"""

from __future__ import annotations

import io
import json
import pickle
import pickletools
import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from sbom import build_sbom, write_sbom  # noqa: E402
from scanner import scan_model, summarize, write_report  # noqa: E402
from scanners import (  # noqa: E402
    DependenciesScanner,
    ModelArtifact,
    PickleOpcodeScanner,
    ProvenanceScanner,
)

DEMO_MODEL = PROJECT_DIR / "samples" / "demo_model"


# ---------------------------------------------------------------------------
# Pickle scanner — clean baseline + malicious construction
# ---------------------------------------------------------------------------


def test_pickle_scanner_does_not_flag_clean_baseline():
    artifact = ModelArtifact(root=DEMO_MODEL)
    findings = PickleOpcodeScanner().scan(artifact)
    # The shipped pytorch_model.bin is a safe pickle of a basic dict; no
    # GLOBAL opcodes referencing non-allowlisted modules → no findings.
    assert findings == [], (
        f"clean baseline pickle should produce zero findings, got {findings}"
    )


def _build_malicious_pickle(path: Path, module: str, callable_name: str,
                            arg: str) -> None:
    """Emit a pickle stream that, on load, would call `module.callable(arg)`.

    The file is constructed by hand from pickle opcodes so we don't actually
    have to define a malicious __reduce__ class. The pickletools.genops
    walk over this stream will surface the malicious GLOBAL ref without
    executing it.
    """
    data = (
        b"\x80\x04"                                   # PROTO 4
        b"c" + module.encode() + b"\n"                # GLOBAL <module>
        + callable_name.encode() + b"\n"
        b"(" + (b"X" + len(arg).to_bytes(4, "little")
                + arg.encode())                       # SHORT_BINUNICODE arg
        + b"tR."                                      # TUPLE, REDUCE, STOP
    )
    path.write_bytes(data)


def test_pickle_scanner_flags_os_system_global(tmp_path):
    """Construct a pickle that references `os.system` via GLOBAL opcode.
    The scanner must surface a critical finding without executing the pickle."""
    bad = tmp_path / "evil_model.bin"
    _build_malicious_pickle(bad, "os", "system", "echo PWNED")

    # Sanity: confirm the file is structurally pickle-shaped (parses).
    list(pickletools.genops(io.BytesIO(bad.read_bytes())))

    findings = PickleOpcodeScanner().scan(ModelArtifact(root=tmp_path))
    assert findings, "malicious pickle must produce at least one finding"
    # The os.system reference is rated critical in our scanner.
    assert any(f.severity == "critical" for f in findings)
    assert any("os" in f.title.lower() for f in findings)


def test_pickle_scanner_flags_subprocess_global(tmp_path):
    bad = tmp_path / "evil2.pkl"
    _build_malicious_pickle(bad, "subprocess", "Popen", "id")
    findings = PickleOpcodeScanner().scan(ModelArtifact(root=tmp_path))
    assert findings
    assert any(f.severity == "critical" for f in findings)
    assert any("subprocess" in f.title.lower() for f in findings)


def test_pickle_scanner_does_not_flag_torch_globals(tmp_path):
    """A pickle that references `torch._tensor._rebuild_tensor_v2` (a real
    PyTorch internal used by torch.save) must be allowed."""
    safe = tmp_path / "torch_like.pt"
    _build_malicious_pickle(safe, "torch._tensor", "_rebuild_tensor_v2", "x")
    findings = PickleOpcodeScanner().scan(ModelArtifact(root=tmp_path))
    assert findings == [], "torch.* GLOBALs must be on the allowlist"


# ---------------------------------------------------------------------------
# Provenance scanner
# ---------------------------------------------------------------------------


def test_provenance_scanner_clean_demo_model():
    """The shipped demo model has README + LICENSE + config.json. The only
    finding it should produce is the missing-manifest informational item."""
    artifact = ModelArtifact(root=DEMO_MODEL)
    findings = ProvenanceScanner().scan(artifact)
    # Manifest is intentionally absent for the demo (low-severity informational).
    assert all(f.severity in {"low", "medium"} for f in findings), (
        f"demo model should not produce high/critical provenance findings; "
        f"got {[(f.title, f.severity) for f in findings]}"
    )


def test_provenance_scanner_flags_missing_model_card(tmp_path):
    # No README, no LICENSE, no config — every required-file finding fires.
    findings = ProvenanceScanner().scan(ModelArtifact(root=tmp_path))
    titles = " ".join(f.title for f in findings).lower()
    assert "model card" in titles
    assert "license" in titles
    assert "config" in titles


# ---------------------------------------------------------------------------
# Dependencies scanner
# ---------------------------------------------------------------------------


def test_deps_scanner_flags_requests_in_demo():
    """The demo requirements.txt declares `requests` — should be flagged."""
    artifact = ModelArtifact(root=DEMO_MODEL)
    findings = DependenciesScanner().scan(artifact)
    assert findings, "demo requirements.txt has at least one risky package"
    titles = " ".join(f.title for f in findings).lower()
    assert "requests" in titles


def test_deps_scanner_flags_git_url_dependency(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text(
        "numpy>=1.24\n"
        "torch>=2.0\n"
        "shady-pkg @ git+https://github.com/attacker/shady.git@main\n",
        encoding="utf-8",
    )
    findings = DependenciesScanner().scan(ModelArtifact(root=tmp_path))
    titles = " ".join(f.title for f in findings).lower()
    assert "git url" in titles


# ---------------------------------------------------------------------------
# SBOM generator
# ---------------------------------------------------------------------------


def test_sbom_for_demo_model_lists_every_file():
    artifact = ModelArtifact(root=DEMO_MODEL)
    bom = build_sbom(artifact, model_name="demo_model")
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert bom["serialNumber"].startswith("urn:uuid:")
    component_paths = {c["name"] for c in bom["components"]}
    expected = {"README.md", "LICENSE", "config.json", "requirements.txt", "pytorch_model.bin"}
    assert expected.issubset(component_paths), (
        f"missing components: {expected - component_paths}"
    )
    # Every component must carry a SHA-256 hash.
    for c in bom["components"]:
        assert c["hashes"], f"component {c['name']} missing hash"
        assert c["hashes"][0]["alg"] == "SHA-256"
        assert len(c["hashes"][0]["content"]) == 64


def test_sbom_writer_produces_valid_json(tmp_path):
    artifact = ModelArtifact(root=DEMO_MODEL)
    out = tmp_path / "sbom.cdx.json"
    write_sbom(artifact, out, model_name="demo_model",
               source_url="https://huggingface.co/example/demo_model")
    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert parsed["specVersion"] == "1.5"
    refs = parsed["metadata"]["component"].get("externalReferences", [])
    assert any(r.get("type") == "distribution" for r in refs)


# ---------------------------------------------------------------------------
# End-to-end orchestrator
# ---------------------------------------------------------------------------


def test_end_to_end_scan_on_demo_model():
    artifact = ModelArtifact(root=DEMO_MODEL)
    n_files = sum(1 for _ in artifact.files())
    findings = scan_model(artifact)
    summary = summarize(findings, n_files)
    # The demo model should produce some findings (requests dep + missing
    # manifest at minimum) but no criticals.
    assert summary["n_findings"] >= 1
    assert summary["by_severity"].get("critical", 0) == 0
    # Every finding from scan_model carries the OWASP/ATLAS/AI RMF mapping.
    for f in findings:
        assert f.owasp_category == "LLM03"
        assert f.atlas_techniques


def test_report_writer_produces_findings_json_and_markdown(tmp_path):
    artifact = ModelArtifact(root=DEMO_MODEL)
    n_files = sum(1 for _ in artifact.files())
    findings = scan_model(artifact)
    summary = summarize(findings, n_files)
    out = tmp_path / "out"
    findings_path, report_path = write_report(findings, summary, DEMO_MODEL, out)
    assert findings_path.exists()
    assert report_path.exists()
    data = json.loads(findings_path.read_text(encoding="utf-8"))
    assert data["run"]["summary"]["n_findings"] == len(findings)
    md = report_path.read_text(encoding="utf-8")
    assert "AI Model Supply Chain Audit" in md
    assert "Severity rollup" in md
