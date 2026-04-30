"""RAG Pipeline Security Auditor.

Static corpus scanner that finds indirect-injection payloads, PII, secrets,
and sensitivity-marker leaks in retrieval-augmented-generation corpora
before they reach a production LLM. Findings are emitted as CIM-shaped
JSON events for Splunk ingestion and a Markdown audit report keyed by
NIST AI RMF subcategory.
"""
