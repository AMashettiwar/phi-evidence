#!/usr/bin/env python3
"""Score the name detector against TAB, a corpus I did not write.

TAB annotates person names in European Court of Human Rights judgments. dev is
for development; test is for measurement and is run once.

It imports name_spans from the detector, so the function being scored is exactly
the function that runs in production. A separate copy in the scorer would let
the two drift apart, which is how a benchmark stops measuring the product.

Run:  python tools/eval_tab_names.py dev
      python tools/eval_tab_names.py test
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "pylibs"))

from phi_scan.detect import name_spans  # noqa: E402

SPLIT = sys.argv[1] if len(sys.argv) > 1 else "test"
TAB = ROOT / "fixtures" / "public" / "tab" / f"echr_{SPLIT}.json"


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return (0.0, 0.0)
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def gold_spans(document: dict) -> list[tuple[int, int]]:
    """PERSON spans, unioned across annotators."""
    annotations = document.get("annotations") or {}
    spans: set[tuple[int, int]] = set()
    if isinstance(annotations, dict):
        for annotator in annotations.values():
            if not isinstance(annotator, dict):
                continue
            for mention in annotator.get("entity_mentions") or []:
                if not isinstance(mention, dict):
                    continue
                if str(mention.get("entity_type", "")).upper() != "PERSON":
                    continue
                if "start_offset" in mention and "end_offset" in mention:
                    spans.add((int(mention["start_offset"]), int(mention["end_offset"])))
    return sorted(spans)


def overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def main() -> int:
    if not TAB.exists():
        print(f"missing {TAB}; run tools/fetch_tab.py first")
        return 2

    documents = json.loads(TAB.read_text(encoding="utf-8"))
    print(f"split              {SPLIT}")
    print(f"documents          {len(documents)}")

    tp = fp = fn = 0
    examples: list[str] = []
    missed: list[str] = []

    for document in documents:
        text = document.get("text") or ""
        gold = gold_spans(document)
        predicted = [(start, end) for start, end, _ in name_spans(text)]

        used = set()
        for span in predicted:
            match = next((i for i, g in enumerate(gold) if i not in used and overlaps(span, g)), None)
            if match is None:
                fp += 1
                if len(examples) < 10:
                    examples.append(text[span[0]:span[1]].replace("\n", " ")[:60])
            else:
                used.add(match)
                tp += 1
        for index, span in enumerate(gold):
            if index not in used:
                fn += 1
                if len(missed) < 10:
                    missed.append(text[span[0]:span[1]].replace("\n", " ")[:60])

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    p_lo, p_hi = wilson(tp, tp + fp)
    r_lo, r_hi = wilson(tp, tp + fn)

    print(f"gold person spans  {tp + fn}")
    print(f"predicted spans    {tp + fp}")
    print(f"true positive      {tp}")
    print(f"false positive     {fp}")
    print(f"false negative     {fn}")
    print()
    print(f"precision          {precision:6.1%}   95% CI {p_lo:.1%} to {p_hi:.1%}")
    print(f"recall             {recall:6.1%}   95% CI {r_lo:.1%} to {r_hi:.1%}")
    print()
    print("sample false positives:")
    for example in examples:
        print(f"  - {example!r}")
    print()
    print("sample misses:")
    for example in missed:
        print(f"  - {example!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
