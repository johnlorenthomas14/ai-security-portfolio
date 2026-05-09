"""LLM Output Safety & Compliance Monitor — library + CLI entry.

Library usage:
    from monitor import OutputMonitor
    mon = OutputMonitor(audit_log_path="audit.jsonl")
    decision = mon.check("LLM-generated response to evaluate")
    if decision.blocked:
        return generic_refusal()
    return decision.response_out

CLI usage — replay a JSONL corpus of historical outputs through the
monitor for compliance backfill:
    python monitor.py --corpus samples/bad_outputs.jsonl --audit-log out/audit.jsonl
    python monitor.py --verify out/audit.jsonl   # integrity check
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from audit import HashChainAuditLog, verify_chain
from filters import (
    Action,
    ClassificationFilter,
    Decision,
    Finding,
    NeMoGuardrailsFilter,
    OutputFilter,
    PIIFilter,
    PolicyFilter,
    SecretsFilter,
)


class OutputMonitor:
    """Orchestrates filters; records every decision to a hash-chained log.

    The default filter chain is the four MVP filters (PII redact, secrets
    block, classification block, policy block). Pass
    ``include_nemo_guardrails=True`` to append the
    ``NeMoGuardrailsFilter`` — an opt-in fifth filter that delegates to
    the portfolio's NeMo Guardrails app for the same secret / classification /
    jailbreak detection vocabulary, expressed as programmable Colang
    rails. Decisions from this layer flow into the same hash-chained
    audit log so audit-chain integrity is preserved.

    Passing an explicit ``filters=...`` list overrides both defaults
    and the include flag — the caller has full control of the chain.
    """

    def __init__(
        self,
        *,
        filters: list[OutputFilter] | None = None,
        audit_log_path: Path | str | None = None,
        include_nemo_guardrails: bool = False,
    ) -> None:
        if filters is not None:
            self.filters: list[OutputFilter] = list(filters)
        else:
            self.filters = [
                PIIFilter(),
                SecretsFilter(),
                ClassificationFilter(),
                PolicyFilter(),
            ]
            if include_nemo_guardrails:
                self.filters.append(NeMoGuardrailsFilter())
        self.audit: HashChainAuditLog | None = (
            HashChainAuditLog(audit_log_path) if audit_log_path else None
        )

    def check(self, response: str) -> Decision:
        findings: list[Finding] = []
        for f in self.filters:
            try:
                findings.extend(f.scan(response))
            except Exception:  # noqa: BLE001 — never let a filter crash the monitor
                continue

        verdict, response_out = self._resolve(response, findings)

        decision = Decision(
            verdict=verdict,
            response_in=response,
            response_out=response_out,
            findings=findings,
        )
        if self.audit is not None:
            entry = self.audit.append(
                decision_verdict=verdict,
                findings=[_finding_summary(f) for f in findings],
                response_in=response,
                response_out=response_out,
            )
            decision.audit_entry_id = entry.entry_id
        return decision

    # ------------------------------------------------------------------

    def _resolve(self, response: str, findings: list[Finding]) -> tuple[str, str]:
        if not findings:
            return "pass", response

        # Highest-precedence action wins. If anything blocks, block.
        action = max((f.action for f in findings), key=lambda a: a.precedence)

        if action == Action.BLOCK:
            return "block", _generic_refusal()

        if action == Action.REDACT:
            return "redact", _apply_redactions(response, findings)

        # FLAG — pass through unchanged.
        return "pass", response


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generic_refusal() -> str:
    return (
        "I cannot share that response. The output was blocked by the "
        "compliance monitor. If you believe this is an error, contact "
        "your administrator and reference the audit trail."
    )


def _apply_redactions(text: str, findings: list[Finding]) -> str:
    """Replace each redact-action finding's matched span with its
    redaction_text. Right-to-left so earlier offsets remain valid."""
    redacts = sorted(
        (f for f in findings if f.action == Action.REDACT),
        key=lambda f: f.matched_span[0],
        reverse=True,
    )
    out = text
    for f in redacts:
        s, e = f.matched_span
        out = out[:s] + f.redaction_text + out[e:]
    return out


def _finding_summary(f: Finding) -> dict[str, Any]:
    """Serialize a Finding for the audit log. Excludes raw matched text
    on critical/high findings — we don't want secrets in the audit log
    itself, only metadata."""
    keep_matched = f.severity not in {"critical", "high"} or f.category == "pii_disclosure"
    return {
        "finding_id": f.finding_id,
        "filter": f.filter_name,
        "category": f.category,
        "action": f.action.value,
        "severity": f.severity,
        "title": f.title,
        "matched_span": list(f.matched_span),
        "matched_text": f.matched_text if keep_matched else "[REDACTED:audit-storage]",
        "owasp": f.owasp_category,
        "atlas": f.atlas_techniques,
        "airmf": f.airmf_subcategory,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def cli_replay(corpus_path: Path, audit_log_path: Path, quiet: bool) -> int:
    mon = OutputMonitor(audit_log_path=audit_log_path)
    counts = {"pass": 0, "redact": 0, "block": 0}
    n = 0

    with corpus_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            response_text = row.get("response", "")
            decision = mon.check(response_text)
            counts[decision.verdict] += 1
            n += 1
            if not quiet:
                v = decision.verdict.upper().ljust(7)
                excerpt = response_text[:80].replace("\n", " ")
                print(f"[{v}] {excerpt}")

    print(
        f"\n{n} responses — "
        f"{counts['pass']} pass · "
        f"{counts['redact']} redact · "
        f"{counts['block']} block"
    )
    print(f"Audit log: {audit_log_path}  ({len(mon.audit) if mon.audit else 0} entries)")
    return 0 if counts["block"] == 0 else 1


def cli_verify(audit_log_path: Path) -> int:
    ok, idx, reason = verify_chain(audit_log_path)
    if ok:
        n = sum(1 for _ in HashChainAuditLog(audit_log_path).entries())
        print(f"Audit chain valid — {n} entries verified.")
        return 0
    print(f"Audit chain BROKEN at entry index {idx}: {reason}")
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="LLM Output Compliance Monitor")
    parser.add_argument("--corpus", default=None,
                        help="JSONL file of LLM responses to replay through the monitor")
    parser.add_argument(
        "--audit-log", default=str(Path(__file__).parent / "out" / "audit.jsonl"),
        help="Path to the hash-chained audit log",
    )
    parser.add_argument("--verify", default=None,
                        help="Verify the integrity of an existing audit log file")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    if args.verify:
        return cli_verify(Path(args.verify))

    if args.corpus:
        Path(args.audit_log).parent.mkdir(parents=True, exist_ok=True)
        return cli_replay(Path(args.corpus), Path(args.audit_log), args.quiet)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
