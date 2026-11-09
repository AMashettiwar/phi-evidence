"""Score the filled blind review packet: reviewer agreement and the detector's.

Reads eval/review_packet.csv after two reviewers have written 'exposure' or
'not_exposure' in reviewer_a and reviewer_b. Reports Cohen's kappa between the
reviewers, and how often the rules arm (eval/results.json ledger) agrees with
each. Until both columns are filled it says so and exits 2: pending human.

Run:  python -m eval.adjudication
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LABELS = ("exposure", "not_exposure")


def cohen_kappa(a: list[str], b: list[str]) -> float:
    agree = sum(x == y for x, y in zip(a, b)) / len(a)
    chance = sum((a.count(label) / len(a)) * (b.count(label) / len(b)) for label in LABELS)
    return 1.0 if chance == 1 else (agree - chance) / (1 - chance)


def main() -> int:
    with (ROOT / "eval" / "review_packet.csv").open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    filled = [r for r in rows if r["reviewer_a"] in LABELS and r["reviewer_b"] in LABELS]
    if len(filled) < len(rows):
        print(f"PENDING HUMAN  {len(filled)}/{len(rows)} items reviewed by both reviewers")
        return 2
    mapping = json.loads((ROOT / "eval" / "review_key.json").read_text(encoding="utf-8"))
    results = json.loads((ROOT / "eval" / "results.json").read_text(encoding="utf-8"))
    wrong = {e["id"] for e in results["ledger"] if e["arm"] == "rules"}
    expected = {i["id"]: i["expected_flag"] for i in json.loads(
        (ROOT / "eval" / "keys" / "corpus_key.json").read_text(encoding="utf-8"))["items"]}
    detector = ["exposure" if expected[mapping[r["review_id"]]] != (mapping[r["review_id"]] in wrong)
                else "not_exposure" for r in rows]
    a, b = [r["reviewer_a"] for r in rows], [r["reviewer_b"] for r in rows]
    print(f"reviewers' kappa        {cohen_kappa(a, b):.3f}")
    print(f"detector vs reviewer A  {sum(x == y for x, y in zip(detector, a))}/{len(rows)}")
    print(f"detector vs reviewer B  {sum(x == y for x, y in zip(detector, b))}/{len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
