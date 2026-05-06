# 06 — AI Model Supply Chain Risk Scanner

[![CI](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml/badge.svg)](https://github.com/johnlorenthomas14/ai-security-portfolio/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![CycloneDX 1.5](https://img.shields.io/badge/CycloneDX-1.5-green.svg)](https://cyclonedx.org/specification/overview/)
[![OWASP LLM03](https://img.shields.io/badge/OWASP%20LLM-LLM03-orange.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

> **Static scanner over a model directory. Detects pickle-based
> code-execution risk in weight files, missing-provenance metadata, and
> risky dependencies declared alongside the model. Emits a CycloneDX 1.5
> SBOM fragment as the supply-chain compliance artifact.** Maps to OWASP
> **LLM03 Supply Chain** — explicitly out of scope for Projects 1–5
> because supply-chain risk is a pre-deployment artifact concern, not a
> runtime detection concern.

**Status:** Working MVP. Ships with three scanner classes (pickle opcode
analysis, provenance check, suspicious dependencies), a CycloneDX 1.5
SBOM generator, a synthetic demo model directory, an 11-test pytest
suite that includes programmatically-constructed malicious pickles, and
a CI job that scans the demo model and validates the emitted SBOM on
every push.

## Demo

[![asciicast](https://asciinema.org/a/JNeREh3m29bJTTeH.svg)](https://asciinema.org/a/JNeREh3m29bJTTeH)

90-second walkthrough — the demo model directory layout, the scanner
running over it (one high-severity `requests` dependency finding, one
low-severity missing-manifest finding), the Markdown audit report,
the emitted CycloneDX 1.5 SBOM fragment with SHA-256 hashes per file,
and the pytest suite (which includes the programmatically-constructed
malicious-pickle path that proves the opcode scanner catches `os.system`
references without executing the pickle). Click the cast above to play,
or run it yourself:

```bash
cd 06-model-supply-chain-scanner
./demo.sh
```

## Threat model

| | |
|---|---|
| **Attacker capability** | Publishes or tampers with a model artifact (weights, tokenizer, config, dependency manifest) that a downstream consumer pulls from HuggingFace, GitHub, an internal artifact registry, or a vendor distribution. |
| **Target asset** | The host that loads the model and any data / credentials / tools the model's loader can reach during deserialization. Pickle-based weight files load via Python's pickle protocol — i.e., they execute arbitrary Python at load time. |
| **In scope** | Pickle-protocol GLOBAL/REDUCE opcodes referencing non-allowlisted modules (`os`, `subprocess`, `socket`, `requests`, …); missing model card / LICENSE / config metadata; risky dependencies declared in shipped `requirements.txt` / `setup.py`; git-URL pinned dependencies; CycloneDX SBOM fragment for downstream supply-chain tooling. |
| **Out of scope (MVP)** | Behavioral / training-time poisoning (requires running the model); steganographic backdoors in weights themselves; safetensors / GGUF format scanning (these are not pickle-based — separate scanner pattern); cryptographic signature verification (ed25519 / Sigstore — clean roadmap addition). |

## Architecture

```
                  Model directory under inspection
                                  │
                                  ▼
            ┌────────────────────────────────────────┐
            │            scan_model()                │
            └────────────────┬───────────────────────┘
                             │
            ┌────────────────┼─────────────────────┐
            ▼                ▼                     ▼
   ┌─────────────────┐ ┌────────────────┐ ┌─────────────────┐
   │ PickleOpcode    │ │ Provenance     │ │ Dependencies    │
   │ Scanner         │ │ Scanner        │ │ Scanner         │
   │                 │ │                │ │                 │
   │ pickletools.    │ │ required-files │ │ regex on        │
   │ genops walk —   │ │ + version meta │ │ requirements.txt│
   │ flag non-allow- │ │ + manifest     │ │ for risky pkgs  │
   │ listed GLOBALs  │ │ presence       │ │ + git-URL deps  │
   └─────────────────┘ └────────────────┘ └─────────────────┘
                             │
                             ▼
            ┌────────────────────────────────────────┐
            │       Aggregated findings              │
            └────────────────┬───────────────────────┘
                             │
                             ▼
            ┌──────────────────┐  ┌────────────────────┐
            │ findings.json    │  │ sbom.cdx.json      │
            │ audit_report.md  │  │ (CycloneDX 1.5)    │
            └──────────────────┘  └────────────────────┘
```

## The three scanners

**`PickleOpcodeScanner`** — the actual security control. Pickle is an
*executable* serialization format: loading a `.pt` / `.pth` / `.pkl` /
`.bin` file with `torch.load()` or `pickle.load()` runs whatever the
malicious author embedded as a `__reduce__` payload. Recent real-world
attacks have used `os.system()`, `subprocess.Popen()`, and `socket`
calls to exfiltrate AWS credentials at model-load time.

The scanner uses Python's `pickletools.genops` to disassemble the
pickle stream **without executing it**. Every `GLOBAL` opcode
references a module + symbol; the scanner inspects each and flags any
reference outside an allowlist of model-related modules (`torch.*`,
`numpy.*`, `collections.*`, builtins, `transformers.*`, etc.). Hard-coded
indicators (`os`, `subprocess`, `socket`, `ctypes`, `requests`, `marshal`,
`exec`, `eval`, `__import__`) are tagged as critical with explicit
rationale. Same approach as `picklescan` and HuggingFace's own
security scanner.

**`ProvenanceScanner`** — checks for required model-distribution
artifacts: README / model card, LICENSE file, config.json with
`model_type` field, integrity manifest (`manifest.json` / `SHA256SUMS`).
Missing any of these is a policy gate, not a security exploit, but
"missing-provenance" is precisely the failure mode that lets a tampered
or rogue model slip into a production environment unnoticed.

**`DependenciesScanner`** — reads any `requirements.txt`,
`setup.py`, `pyproject.toml`, or environment manifest shipped alongside
the model. Flags risky package categories — outbound-network libraries
(`requests`, `httpx`, `aiohttp`), packet-craft libraries (`scapy`,
`pyshark`), known typosquats (`requesocks`, `urllib` — stdlib pretender),
extended-pickle libraries (`dill`, `cloudpickle`), system-control
libraries (`subprocess32`, `psutil`, `ctypes`). Also flags git-URL
pinned dependencies (`shady-pkg @ git+https://...`) since those bypass
package-index policy controls.

## CycloneDX SBOM fragment

CycloneDX 1.5 is the de-facto SBOM standard for software supply chain.
The scanner emits a JSON SBOM fragment listing every file in the model
directory as a component with:

- The relative path as the component `name`
- A SHA-256 hash of the file contents under `hashes`
- A guessed MIME type
- The model directory itself as `metadata.component` of type
  `machine-learning-model`
- An optional `externalReferences.distribution` URL recording where the
  model came from

Output integrates with the standard supply-chain toolchain — Anchore,
Snyk, Trivy, GitHub Dependabot all consume CycloneDX. Treating the
model artifact as a first-class SBOM-able entity is the GRC pattern
this project demonstrates.

## Quick start

```bash
cd 06-model-supply-chain-scanner
pip install -r requirements.txt

# Scan the shipped demo model
python3 scanner.py --model samples/demo_model

# Output structure
ls out/
#   findings.json    audit_report.md    sbom.cdx.json

# Inspect the audit report
head -40 out/audit_report.md

# Inspect the SBOM
head -25 out/sbom.cdx.json

# Tests (offline; includes programmatically-constructed malicious pickles
# in tmp_path so no real malicious files ship in the repo)
pytest -q
```

## Why we don't ship a real malicious pickle

The pickle scanner has to detect pickles that reference dangerous
modules — but committing a real pickle that resolves `os.system` to a
file in the public repo is irresponsible. Even if it's labeled "for
testing," a careless cloner could `torch.load()` it.

Instead, the test suite **constructs malicious pickle bytestrings
programmatically in `tmp_path`** using a hand-built sequence of pickle
opcodes (`GLOBAL os system`, `(arg)`, `REDUCE`, `STOP`). The scanner
walks these with `pickletools.genops` (which does *not* execute the
pickle) and confirms it flags the opcodes. The malicious file lives
only in the test runner's temp directory and is deleted at end of run.
The shipped demo model's `pytorch_model.bin` is a clean baseline pickle
of a basic Python dict — no GLOBAL opcodes at all.

## Splunk integration

Each finding emits a CIM-shaped JSON event, ready for Splunk HEC
ingestion. Project 4's correlation generator already includes rule
templates that consume `cim_eventtype="ai_model_supply_chain_finding"`
events — wire the scanner output into HEC and the existing correlation
rules fire automatically on critical / high findings:

```spl
index=aisec sourcetype="aisec:supply_chain" cim_eventtype="ai_model_supply_chain_finding" severity IN ("critical","high")
| stats count values(category) as categories values(scanner) as scanners
        by artifact_path
| `notable_event(model_supply_chain_finding, "high", "Model artifact failed supply-chain scan")`
```

## What's not in MVP (roadmap)

- **Cryptographic signature verification.** Sigstore / cosign signature
  verification on the model directory's manifest. This would close the
  provenance gap — currently the scanner can confirm a manifest *exists*
  but not that it was signed by the expected publisher.
- **safetensors and GGUF format scanning.** These are not pickle-based
  (`safetensors` is structurally restricted, GGUF is a binary tensor
  format), so they need different scanners. The right architecture is
  one scanner per format with a shared `Scanner` protocol.
- **Behavioral pickle scanning.** Run the pickle in a sandboxed
  environment (gVisor, Firecracker, or an unprivileged container)
  and observe its actual loaded behavior. Catches obfuscated payloads
  the static GLOBAL-walker misses. Higher operational complexity but
  necessary at production trust levels.
- **Vulnerability cross-reference.** Cross-reference the SBOM
  components against published CVEs (NVD, OSV, GitHub Advisory) to
  surface known-vulnerable dependencies — same pattern Trivy / Snyk
  apply to traditional SBOMs, applied to model dependency manifests.
- **Cross-corpus calibration.** Run the scanner against published
  malicious-model corpora (HuggingFace's own picklescan dataset, the
  ProtectAI ml-malicious-models repo) for true-/false-positive rate
  measurement against external ground truth.

## Why this matters for the portfolio

LLM03 Supply Chain is the OWASP category Projects 1–5 deliberately
left out of scope. The reason: supply-chain risk is a *pre-deployment*
artifact concern that needs a different shape from the
runtime / corpus / detection-content patterns the rest of the portfolio
implements. Project 6 fills that gap with the same engineering
discipline — measurable scanners, deterministic CI gates, structured
output that flows into the same Splunk pipeline as Projects 1–5, and a
compliance artifact (the SBOM) that integrates with the broader
software-supply-chain tooling the security industry already runs.

The pickle scanner specifically is the project that pulls the most
weight in interview conversations. *"How do you check that an
open-source model from HuggingFace is safe to load?"* is one of the
five most-asked AI-security questions in 2026, and most candidates
answer it with hand-waving about "trusted sources" or "signed
artifacts." A working pickle scanner with an allowlist of model-related
modules and a programmatically-validated test against malicious
opcodes is a concrete, demonstrable answer that goes well beyond the
hand-waving.
