"""SIEM Correlation Rule Generator — CLI entry.

Loads every YAML rule template under `templates/`, runs every generator
(Splunk ES, Sigma, Cortex XSIAM, NVIDIA Morpheus) over each rule, and
writes platform-native detection content to ``out/<platform>/<rule_id>.<ext>``.
Also emits a Markdown coverage map showing which rules cover which
OWASP / ATLAS / AI RMF cells.

Usage:
    python generator.py
    python generator.py --templates templates --output ./out
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rules import (
    CortexXSIAMGenerator,
    MorpheusGenerator,
    Rule,
    RuleGenerator,
    SigmaGenerator,
    SplunkESGenerator,
    load_rules,
)


def emit_all(rules: list[Rule], generators: list[RuleGenerator], out_dir: Path) -> int:
    """Write every (rule, generator) cross product to disk. Return file count."""
    written = 0
    for gen in generators:
        target_dir = out_dir / gen.output_subdir
        target_dir.mkdir(parents=True, exist_ok=True)
        for rule in rules:
            content = gen.render(rule)
            target_file = target_dir / f"{gen.filename(rule)}{gen.file_extension}"
            target_file.write_text(content, encoding="utf-8")
            written += 1
    return written


def write_coverage_map(rules: list[Rule], out_dir: Path) -> Path:
    """Markdown table — which rule covers which OWASP / ATLAS / AI RMF cell."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "coverage_map.md"

    lines: list[str] = []
    lines.append("# Detection Coverage Map")
    lines.append("")
    lines.append(
        "Each row shows one canonical rule from the template library. "
        "The same rule produces detection content for Splunk ES, Sigma, "
        "Cortex XSIAM, and NVIDIA Morpheus — see the per-platform output "
        "directories."
    )
    lines.append("")
    lines.append("| Rule ID | Name | Severity | Source event | OWASP | ATLAS | AI RMF |")
    lines.append("|---|---|---|---|---|---|---|")
    for rule in sorted(rules, key=lambda r: r.id):
        lines.append(
            f"| `{rule.id}` | {rule.name} | {rule.severity} "
            f"| `{rule.event_type}` | {rule.owasp_llm} "
            f"| {', '.join(rule.mitre_atlas) or '—'} | {rule.airmf} |"
        )
    lines.append("")

    # Per-OWASP rollup so a reviewer sees the framework's coverage at a glance.
    by_owasp: dict[str, list[str]] = {}
    for rule in rules:
        by_owasp.setdefault(rule.owasp_llm or "(unmapped)", []).append(rule.id)
    lines.append("## OWASP LLM Top 10 (2025) coverage")
    lines.append("")
    lines.append("| OWASP category | Rules |")
    lines.append("|---|---|")
    for cat, ids in sorted(by_owasp.items()):
        lines.append(f"| {cat} | {', '.join(sorted(ids))} |")
    lines.append("")

    # Per-AI-RMF rollup so the GRC reviewer can see continuous-monitoring
    # evidence coverage by subcategory.
    by_airmf: dict[str, list[str]] = {}
    for rule in rules:
        by_airmf.setdefault(rule.airmf or "(unmapped)", []).append(rule.id)
    lines.append("## NIST AI RMF 1.0 subcategory coverage")
    lines.append("")
    lines.append("| AI RMF subcategory | Rules |")
    lines.append("|---|---|")
    for sub, ids in sorted(by_airmf.items()):
        lines.append(f"| {sub} | {', '.join(sorted(ids))} |")
    lines.append("")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SIEM Correlation Rule Generator")
    parser.add_argument(
        "--templates", default=str(Path(__file__).parent / "templates"),
        help="Directory containing canonical YAML rule templates",
    )
    parser.add_argument(
        "--output", default=str(Path(__file__).parent / "out"),
        help="Output directory; per-platform subdirectories created automatically",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    rules = load_rules(args.templates)
    generators: list[RuleGenerator] = [
        SplunkESGenerator(),
        SigmaGenerator(),
        CortexXSIAMGenerator(),
        MorpheusGenerator(),
    ]

    n = emit_all(rules, generators, out_dir)
    coverage_path = write_coverage_map(rules, out_dir)

    if not args.quiet:
        print(f"Loaded {len(rules)} canonical rules from {args.templates}")
        print(f"Generated {n} detection-content files across "
              f"{len(generators)} platforms in {out_dir}/")
        for gen in generators:
            sub = out_dir / gen.output_subdir
            count = len(list(sub.glob(f"*{gen.file_extension}")))
            print(f"  {gen.name}: {count} files in {sub}/")
        print(f"Coverage map: {coverage_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
