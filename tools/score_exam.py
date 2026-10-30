#!/usr/bin/env python3
"""Score the scanner against the exam answer key.

The key marks every item as `phi` (must be found), `trap` (looks like PHI but is
not; must be ignored) or `excluded` (real data that is not PHI). That makes a
proper precision/recall measurement possible, with the traps doing the work a
negative corpus usually has to do.

Matching is by digest, so no key value is ever printed. A finding matches an item
when the sha256 of any of the item's accepted forms appears in the finding's
value_hashes for the same document.

Run:
    python tools/score_exam.py <key.json> [--out artifacts/exam-current]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "pylibs"))

from phi_scan.detect import detect, digest  # noqa: E402


def forms(item: dict) -> set[str]:
    """Every string a finding could legitimately be hashed as."""
    raw = [item.get("value") or ""]
    raw += list(item.get("alt") or [])
    out: set[str] = set()

    def add(text: str) -> None:
        text = " ".join(text.split())
        if text:
            out.add(text)
            out.add(text.upper())
            out.add(text.lower())
            out.add(text.title())

    for value in raw:
        value = value.strip()
        if not value:
            continue
        add(value)
        # HL7 and DICOM name separators: "OKONKWO^ADAEZE^N" also means
        # "Adaeze Okonkwo" and "Adaeze N Okonkwo".
        if "^" in value:
            parts = [p for p in value.split("^") if p]
            if len(parts) >= 2:
                last, first = parts[0], parts[1]
                for combo in (f"{first} {last}", f"{last} {first}",
                              f"{last}, {first}", f"{first} {last} {parts[2]}" if len(parts) > 2 else ""):
                    add(combo)
        if value.count(",") == 1:
            last, first = [p.strip() for p in value.split(",")]
            if last and first:
                add(f"{first} {last}")
                add(f"{last} {first}")
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("key")
    parser.add_argument("--out", default="artifacts/exam-current")
    args = parser.parse_args()

    key = json.loads(Path(args.key).read_text(encoding="utf-8"))
    items = key["items"]
    out = ROOT / args.out

    if not (out / "index.jsonl").exists():
        print(f"no scan output at {out}; run the exam collect first")
        return 2

    findings = detect(out / "index.jsonl", out / "vault", extended=True)

    # doc -> set of digests reported
    reported: dict[str, set[str]] = defaultdict(set)
    per_doc_count: Counter[str] = Counter()
    for finding in findings:
        reported[finding["path"].split("/")[-1].split(".")[0]] |= set(finding["value_hashes"])
        per_doc_count[finding["path"]] += 1

    kinds = Counter(item["kind"] for item in items)
    print("=" * 74)
    print("EXAM SCORE")
    print("=" * 74)
    print(f"findings produced   {len(findings)}")
    print(f"key items           {len(items)}  "
          + "  ".join(f"{k} {v}" for k, v in sorted(kinds.items())))
    print()

    matched = missed = 0
    trap_hits = 0
    excluded_hits = 0
    missed_by_cat: Counter[str] = Counter()
    by_tier: dict[int, list[int]] = defaultdict(lambda: [0, 0])

    for item in items:
        doc = item["doc"]
        hashes = reported.get(doc, set())
        hit = any(digest(f) in hashes for f in forms(item))
        if item["kind"] == "phi":
            tier = item.get("tier") or 0
            by_tier[tier][1] += 1
            if hit:
                matched += 1
                by_tier[tier][0] += 1
            else:
                missed += 1
                missed_by_cat[item["cat"]] += 1
        elif item["kind"] == "trap" and hit:
            trap_hits += 1
        elif item["kind"] == "excluded" and hit:
            excluded_hits += 1

    phi_total = matched + missed
    recall = matched / phi_total if phi_total else 0.0
    precision = matched / (matched + trap_hits + excluded_hits) if matched else 0.0

    print(f"PHI found           {matched}/{phi_total}   recall    {recall:6.1%}")
    print(f"traps reported      {trap_hits}/{kinds.get('trap', 0)}   "
          f"(false positives)")
    print(f"excluded reported   {excluded_hits}/{kinds.get('excluded', 0)}")
    print(f"precision           {precision:6.1%}")
    print()
    print("recall by tier:")
    for tier in sorted(by_tier):
        got, total = by_tier[tier]
        print(f"   tier {tier}   {got:3}/{total:3}   {got / total:6.1%}")
    print()
    print(f"missed {missed} PHI items across {len(missed_by_cat)} categories; worst:")
    for cat, count in missed_by_cat.most_common(12):
        print(f"   {cat:<24} {count}")

    # Per document: did we reach it at all, and how much of it.
    print()
    print("per document (found/total PHI, findings on that file):")
    per_doc: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for item in items:
        if item["kind"] != "phi":
            continue
        doc = item["doc"]
        per_doc[doc][1] += 1
        hashes = reported.get(doc, set())
        if any(digest(f) in hashes for f in forms(item)):
            per_doc[doc][0] += 1
    for doc in sorted(per_doc):
        got, total = per_doc[doc]
        count = sum(v for k, v in per_doc_count.items() if k.split("/")[-1].startswith(doc))
        flag = "MISS" if got == 0 else ("ok  " if got == total else "part")
        print(f"   {flag} {doc:<24} {got:3}/{total:3}   findings={count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
