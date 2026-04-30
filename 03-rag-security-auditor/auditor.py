"""RAG Pipeline Security Auditor — CLI entry.

Loads every readable text document under a corpus directory, runs every
DocumentScanner against each, aggregates findings, and writes
``findings.json`` + ``audit_report.md`` to the output directory.

Usage:
    # Quick demo against the shipped vulnerable corpus
    python auditor.py --corpus corpus/demo --output ./out

    # Audit a real RAG corpus
    python auditor.py --corpus /path/to/corpus --output ./out
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanners import (
    Document,
    Finding,
    IndirectInjectionScanner,
    PIIScanner,
    SecretsScanner,
    SensitivityScanner,
)


# Recognized text-document extensions. Binary formats (PDFs, DOCX, etc.)
# are roadmap items — extracting clean text from them needs an extra
# library and is out of MVP scope.
_TEXT_EXTENSIONS = {".md", ".txt", ".rst", ".html", ".htm", ".csv", ".json", ".yaml", ".yml"}


def load_corpus(root: Path) -> list[Document]:
    """Walk `root` and load every recognized text document."""
    if not root.exists():
        raise FileNotFoundError(f"Corpus directory not found: {root}")
    docs: list[Document] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in _TEXT_EXTENSIONS:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                text = path.read_text(encoding="latin-1")
            except Exception:  # noqa: BLE001
                continue
        docs.append(
            Document(
                path=path,
                text=text,
                relative_path=str(path.relative_to(root)),
            )
        )
    return docs


def scan_corpus(docs: list[Document]) -> list[dict[str, Any]]:
    """Run all scanners over all documents; return CIM-ready finding dicts."""
    scanners = [
        IndirectInjectionScanner(),
        PIIScanner(),
        SecretsScanner(),
        SensitivityScanner(),
    ]

    findings: list[dict[str, Any]] = []
    for doc in docs:
        for scanner in scanners:
            for f in scanner.scan(doc):
                findings.append(_to_event(f))
    return findings


def _to_event(f: Finding) -> dict[str, Any]:
    severity_map = {
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }
    return {
        "finding_id": f.finding_id,
        "scanner": f.scanner,
        "category": f.category,
        "severity": f.severity,
        "title": f.title,
        "document_path": f.document_path,
        "line_number": f.line_number,
        "excerpt": f.excerpt,
        "owasp_category": f.owasp_category,
        "atlas_techniques": f.atlas_techniques,
        "airmf_subcategory": f.airmf_subcategory,
        "rationale": f.rationale,
        # Splunk-friendly CIM fields
        "cim_eventtype": "ai_rag_finding",
        "signature": "rag_security_auditor",
        "event_severity": severity_map.get(f.severity, "low"),
        "event_time": datetime.now(timezone.utc).isoformat(),
    }


def summarize(findings: list[dict[str, Any]], n_documents: int) -> dict[str, Any]:
    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_doc: dict[str, int] = {}
    by_owasp: dict[str, int] = {}
    by_airmf: dict[str, int] = {}
    for f in findings:
        by_category[f["category"]] = by_category.get(f["category"], 0) + 1
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
        by_doc[f["document_path"]] = by_doc.get(f["document_path"], 0) + 1
        by_owasp[f["owasp_category"]] = by_owasp.get(f["owasp_category"], 0) + 1
        by_airmf[f["airmf_subcategory"]] = by_airmf.get(f["airmf_subcategory"], 0) + 1
    return {
        "n_documents": n_documents,
        "n_findings": len(findings),
        "by_category": by_category,
        "by_severity": by_severity,
        "by_document": by_doc,
        "by_owasp": by_owasp,
        "by_airmf": by_airmf,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RAG Security Auditor")
    parser.add_argument(
        "--corpus", default=str(Path(__file__).parent / "corpus" / "demo"),
        help="Corpus directory to audit",
    )
    parser.add_argument(
        "--output", default=str(Path(__file__).parent / "out"),
        help="Output directory for findings.json + audit_report.md",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    corpus_root = Path(args.corpus).resolve()
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    docs = load_corpus(corpus_root)
    findings = scan_corpus(docs)
    summary = summarize(findings, len(docs))

    if not args.quiet:
        print(f"Audited {summary['n_documents']} documents → {summary['n_findings']} findings")
        print(
            "  Severity:  "
            f"critical={summary['by_severity'].get('critical', 0)}  "
            f"high={summary['by_severity'].get('high', 0)}  "
            f"medium={summary['by_severity'].get('medium', 0)}  "
            f"low={summary['by_severity'].get('low', 0)}"
        )
        for f in findings:
            print(
                f"  [{f['severity'].upper():<8}] {f['document_path']}"
                f"{':' + str(f['line_number']) if f['line_number'] else ''}  "
                f"{f['title']}"
            )

    # Defer report writing to report.py for clean module separation.
    from report import write_reports  # noqa: I001
    write_reports(
        findings=findings,
        summary=summary,
        corpus_root=corpus_root,
        out_dir=out_dir,
    )
    print(f"Wrote {out_dir}/findings.json and {out_dir}/audit_report.md")

    # Exit non-zero on any critical/high finding so this can gate CI / pre-merge.
    severe = summary["by_severity"].get("critical", 0) + summary["by_severity"].get("high", 0)
    return 1 if severe else 0


if __name__ == "__main__":
    sys.exit(main())
