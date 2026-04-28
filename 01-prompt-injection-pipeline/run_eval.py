"""Eval harness for the prompt-injection detector.

Reads eval_set.jsonl, runs the detector, prints a confusion matrix and
precision/recall/F1. Defaults to --offline (heuristic-only) so the eval
runs deterministically in CI with no API key.

Usage:
    python run_eval.py                  # heuristic-only, the default
    python run_eval.py --use-judge      # consult the LLM judge (needs API key)
    python run_eval.py --eval other.jsonl
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from detector import DetectorConfig, PromptInjectionDetector

# Treat both "suspicious" and "malicious" as "positive" for binary scoring.
POSITIVE_VERDICTS = {"suspicious", "malicious"}
POSITIVE_LABELS = {"suspicious", "malicious"}


def load(path: Path) -> list[dict]:
    rows = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        rows.append(json.loads(ln))
    return rows


def score(rows: list[dict], detector: PromptInjectionDetector) -> dict:
    tp = fp = tn = fn = 0
    per_category: Counter[str] = Counter()
    per_category_correct: Counter[str] = Counter()
    mistakes: list[dict] = []

    for row in rows:
        verdict = detector.detect(row["text"])
        is_positive_pred = verdict["verdict"] in POSITIVE_VERDICTS
        is_positive_label = row["label"] in POSITIVE_LABELS
        category = row.get("category", "unknown")

        per_category[category] += 1

        if is_positive_pred and is_positive_label:
            tp += 1
            per_category_correct[category] += 1
        elif is_positive_pred and not is_positive_label:
            fp += 1
            mistakes.append({"id": row["id"], "type": "FP", "predicted": verdict["verdict"], "label": row["label"], "text": row["text"][:120]})
        elif not is_positive_pred and not is_positive_label:
            tn += 1
            per_category_correct[category] += 1
        else:
            fn += 1
            mistakes.append({"id": row["id"], "type": "FN", "predicted": verdict["verdict"], "label": row["label"], "text": row["text"][:120]})

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / max(len(rows), 1)

    return {
        "n": len(rows),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "accuracy": round(accuracy, 3),
        "per_category": {k: f"{per_category_correct[k]}/{per_category[k]}" for k in sorted(per_category)},
        "mistakes": mistakes,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--eval", default="eval_set.jsonl")
    parser.add_argument("--use-judge", action="store_true", help="Consult the LLM judge (needs API key)")
    args = parser.parse_args()

    rows = load(Path(args.eval))
    detector = PromptInjectionDetector(DetectorConfig(use_llm_judge=args.use_judge))
    results = score(rows, detector)

    print(json.dumps({k: v for k, v in results.items() if k != "mistakes"}, indent=2))
    if results["mistakes"]:
        print("\nMistakes:")
        for m in results["mistakes"]:
            print(f"  [{m['type']}] {m['id']}: predicted={m['predicted']} label={m['label']}  {m['text']!r}")
    return 0 if results["f1"] >= 0.8 else 1


if __name__ == "__main__":
    raise SystemExit(main())
