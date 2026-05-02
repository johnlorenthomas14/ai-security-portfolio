"""AI Model Supply Chain Risk Scanner.

Static scanner over a model directory. Detects pickle-based code-execution
risk in weight files, broken provenance metadata, and suspicious
dependencies shipped alongside the model. Emits a CycloneDX 1.5 SBOM
fragment as the compliance artifact.

Maps to OWASP LLM03 Supply Chain — explicitly out of scope for Projects
1-5 because it's a pre-deployment artifact concern, not a runtime
detection concern.
"""
