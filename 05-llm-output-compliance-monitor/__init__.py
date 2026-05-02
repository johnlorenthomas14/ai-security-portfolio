"""LLM Output Safety & Compliance Monitor.

A runtime output guardrail. Receives an LLM-generated response, runs it
through four output filters (PII, secrets, classification markers, policy
violations), and produces a Decision: pass, redact, or block. Every
decision is appended to a hash-chained, tamper-evident audit log that
satisfies FedRAMP-style integrity-evidence requirements.

Designed to be embeddable as a library in any LLM application, with a
CLI for batch / replay evaluation against a JSONL corpus of historical
outputs (the "compliance backfill" use case).
"""
