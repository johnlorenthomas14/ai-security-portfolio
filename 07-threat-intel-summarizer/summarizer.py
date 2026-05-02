"""Threat Intelligence Summarizer — CLI entry.

Walks a directory of STIX bundles, generates a cited brief per bundle
(via Claude or the offline stub), verifies citations, and writes:

    out/briefs/<bundle>.md          — the analyst-readable brief
    out/notables/<bundle>.json      — per-bundle Splunk notable events
    out/citation_audit.json         — per-bundle citation summary

Usage:
    python summarizer.py
    python summarizer.py --bundles samples/stix_bundles --output ./out
    python summarizer.py --offline      # force the stub client
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from brief import BriefGenerator
from feed import iter_bundles, load_bundle
from notables import emit_notables


def process_bundle(generator: BriefGenerator, bundle_path: Path,
                    out_dir: Path) -> dict[str, Any]:
    bundle = load_bundle(bundle_path)
    brief = generator.generate(bundle)

    # Brief markdown.
    briefs_dir = out_dir / "briefs"
    briefs_dir.mkdir(parents=True, exist_ok=True)
    (briefs_dir / f"{bundle_path.stem}.md").write_text(
        brief.markdown, encoding="utf-8",
    )

    # Notable events.
    notables_dir = out_dir / "notables"
    notables_dir.mkdir(parents=True, exist_ok=True)
    notables = emit_notables(bundle)
    (notables_dir / f"{bundle_path.stem}.json").write_text(
        json.dumps({"bundle_id": bundle.bundle_id, "events": notables}, indent=2),
        encoding="utf-8",
    )

    return {
        "bundle_path": str(bundle_path),
        "bundle_id": bundle.bundle_id,
        "n_objects": len(bundle),
        "n_indicators_emitted": len(notables),
        "generator": brief.generator,
        "citations": brief.citation_summary,
        "hallucinated_citations": [
            f.citation for f in brief.citations if not f.resolved
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Threat Intelligence Summarizer")
    parser.add_argument(
        "--bundles", default=str(Path(__file__).parent / "samples" / "stix_bundles"),
        help="Directory of STIX 2.1 JSON bundles to summarize",
    )
    parser.add_argument(
        "--output", default=str(Path(__file__).parent / "out"),
        help="Output directory for briefs/, notables/, and citation_audit.json",
    )
    parser.add_argument("--offline", action="store_true",
                        help="Force the stub client (no API calls)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    generator = BriefGenerator(offline=args.offline)
    audit_results: list[dict[str, Any]] = []

    for bundle_path, _bundle in iter_bundles(args.bundles):
        result = process_bundle(generator, bundle_path, out_dir)
        audit_results.append(result)
        if not args.quiet:
            cs = result["citations"]
            print(
                f"  {bundle_path.name}  ({result['n_objects']} objects, "
                f"{result['n_indicators_emitted']} indicators emitted) "
                f"— generator={result['generator']}  "
                f"citations: {cs['n_resolved']}/{cs['n_unique_citations']} resolved"
            )
            if result["hallucinated_citations"]:
                print(f"    HALLUCINATIONS: {result['hallucinated_citations']}")

    # Write the citation audit document.
    audit_path = out_dir / "citation_audit.json"
    audit_path.write_text(
        json.dumps({
            "bundles_processed": len(audit_results),
            "total_hallucinations": sum(
                len(r["hallucinated_citations"]) for r in audit_results
            ),
            "results": audit_results,
        }, indent=2),
        encoding="utf-8",
    )

    print(f"\nProcessed {len(audit_results)} bundle(s) into {out_dir}/")
    print(f"Wrote {audit_path}")

    # Exit non-zero if any brief had hallucinated citations — useful as
    # a CI / pre-distribution gate.
    total_hall = sum(len(r["hallucinated_citations"]) for r in audit_results)
    return 1 if total_hall else 0


if __name__ == "__main__":
    sys.exit(main())
