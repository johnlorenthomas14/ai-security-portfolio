"""NeMoGuardrailsFilter — wraps the portfolio-root NeMo Guardrails app
as an additional output filter for Project 5's monitor chain.

Action: BLOCK on any match. The filter delegates to the synchronous
``check_output(text)`` helper exposed by ``nemo_guardrails/actions.py``
which itself runs three output rails (secret leak, classification
spillage, jailbreak acknowledgement).

This filter is **opt-in**. The monitor's default filter list is
unchanged — the four existing filters (PII redact, secrets block,
classification block, policy block) still run on every check. The
NeMo Guardrails filter is added only when ``OutputMonitor`` is
constructed with ``include_nemo_guardrails=True``.

The filter is intentionally lazy about the import — if the
``nemo_guardrails`` directory is missing or the action module fails
to import, ``scan()`` returns an empty list and the monitor's other
filters proceed unaffected. That keeps Project 5 deployable in
environments that don't include the NeMo Guardrails layer.

Decisions emitted by this filter flow into the existing hash-chained
audit log with ``filter="nemo_guardrails"`` so audit-chain integrity
is preserved across the layered detection.
"""

from __future__ import annotations

from .base import Action, Finding


# Map a Guardrails action's `reason` field (the rule label that fired)
# to the OWASP / MITRE ATLAS / NIST AI RMF tags Project 5's audit log
# expects. Mirrors the per-filter tagging in secrets_filter.py,
# classification_filter.py, and policy_filter.py so a finding from
# this layer is indistinguishable in shape from a finding from the
# existing filters.
_REASON_TAGS: dict[str, dict[str, str | list[str]]] = {
    "secret_leak": {
        "kind": "nemo_secret_leak",
        "severity": "critical",
        "owasp": "LLM02",
        "atlas": ["AML.T0024"],
        "airmf": "MEASURE 2.10",
        "title_kind": "credential material",
    },
    "classification_spillage": {
        "kind": "nemo_classification_spillage",
        "severity": "critical",
        "owasp": "LLM02",
        "atlas": ["AML.T0024"],
        "airmf": "GOVERN 1.3",
        "title_kind": "controlled-handling marker",
    },
    "jailbreak_acknowledgement": {
        "kind": "nemo_jailbreak_acknowledgement",
        "severity": "high",
        "owasp": "LLM01",
        "atlas": ["AML.T0054"],
        "airmf": "MEASURE 2.6",
        "title_kind": "jailbreak-acknowledgement marker",
    },
}

# Fallback used when Guardrails returns a reason we don't recognize —
# unlikely in practice (the action layer's reason set is fixed) but
# defensive against future Guardrails-side additions.
_DEFAULT_TAGS: dict[str, str | list[str]] = {
    "kind": "nemo_unknown",
    "severity": "high",
    "owasp": "LLM01",
    "atlas": ["AML.T0051"],
    "airmf": "MEASURE 2.6",
    "title_kind": "policy violation",
}


class NeMoGuardrailsFilter:
    """Output rail wrapper around the portfolio's NeMo Guardrails app."""

    name = "nemo_guardrails"
    category = "nemo_guardrails_violation"

    def scan(self, text: str) -> list[Finding]:
        check_output = type(self)._load_check_output()
        if check_output is None:
            return []

        try:
            result = check_output(text)
        except Exception:  # noqa: BLE001 — never let the filter crash the monitor
            return []

        if not result.is_unsafe:
            return []

        # The action's reason field is shaped like ``"<rule_label> matched"``.
        # Strip the suffix to recover the canonical rule label used in the
        # tag map.
        rule_label = result.reason.split(" matched", 1)[0]
        tags = _REASON_TAGS.get(rule_label, _DEFAULT_TAGS)

        matched = result.matched_pattern or ""
        idx = text.find(matched) if matched else -1
        span = (idx, idx + len(matched)) if idx >= 0 else (0, 0)

        return [
            Finding(
                finding_id=f"OUT-NEMO-{tags['kind']}-{span[0]}",
                filter_name=self.name,
                category="policy_violation",
                action=Action.BLOCK,
                severity=str(tags["severity"]),
                title=(
                    f"NeMo Guardrails output rail fired — "
                    f"{tags['title_kind']} ({rule_label})"
                ),
                matched_span=span,
                matched_text=matched,
                redaction_text="[BLOCKED:NEMO_GUARDRAILS]",
                rationale=(
                    f"NeMo Guardrails output rail '{rule_label}' matched a "
                    f"{tags['title_kind']} pattern in the LLM response. The "
                    "monitor's BLOCK precedence applies; the response will "
                    "not be returned to the caller. This finding is layered "
                    "on top of Project 5's four existing output filters and "
                    "demonstrates the portfolio's integration with NVIDIA's "
                    "programmable-guardrails framework."
                ),
                owasp_category=str(tags["owasp"]),
                atlas_techniques=list(tags["atlas"]),  # type: ignore[arg-type]
                airmf_subcategory=str(tags["airmf"]),
            )
        ]

    @staticmethod
    def _load_check_output():
        """Lazy-import the portfolio's NeMo Guardrails action layer.

        Importing here (not at module top) means Project 5 can be
        deployed without a ``nemo_guardrails/`` directory present —
        the filter simply returns an empty list when the action layer
        isn't reachable.
        """
        try:
            from pathlib import Path
            import sys as _sys

            # filters/nemo_guardrails_filter.py → ../../nemo_guardrails/
            nemo_dir = (
                Path(__file__).resolve().parent.parent.parent / "nemo_guardrails"
            )
            if str(nemo_dir) not in _sys.path:
                _sys.path.insert(0, str(nemo_dir))
            from actions import check_output  # type: ignore[import-not-found]
            return check_output
        except Exception:  # noqa: BLE001
            return None
