# AI Model Supply Chain Audit

**Model root:** `/Users/johnthomas/Documents/Claude/ai-security-portfolio/06-model-supply-chain-scanner/samples/demo_model`  
**Files scanned:** 5  
**Findings:** 2

## Severity rollup

| Critical | High | Medium | Low |
|---:|---:|---:|---:|
| 0 | 1 | 0 | 1 |

## Findings by scanner

| Scanner | Findings |
|---|---:|
| dependencies_scanner | 1 |
| provenance_scanner | 1 |

## Detailed findings

### [HIGH] `MS-DEP-risky_requests-requirements.txt` — Risky dependency declared — requests

- **Artifact:** `requirements.txt` (line L5)  · **Scanner:** dependencies_scanner  · **Category:** risky_dependency
- **OWASP:** LLM03  · **ATLAS:** AML.T0010  · **AI RMF:** MAP 4.1
- **Rationale:** Model distribution declares 'requests' as a dependency: outbound HTTP capability inside model load path. Inference-only models rarely need this category of dependency; verify it's required for the loader path before approving for deployment.

**Evidence:**

```
requests>=2.31
```

### [LOW] `MS-PRV-missing_manifest` — Model directory has no integrity manifest

- **Artifact:** `<directory>` (line —)  · **Scanner:** provenance_scanner  · **Category:** missing_provenance
- **OWASP:** LLM03  · **ATLAS:** AML.T0010  · **AI RMF:** MAP 4.1
- **Rationale:** No manifest.json / SHA256SUMS / checksums.json found. Without a signed manifest, individual weight-file integrity cannot be verified independently of the directory's transport mechanism. Generated SBOM (sbom.cdx.json) provides this artifact going forward.

