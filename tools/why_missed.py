#!/usr/bin/env python3
"""Why did each PHI item get missed? Group the misses by cause."""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "pylibs"))

from phi_scan.detect import detect, digest  # noqa: E402
from phi_scan.detect import identifiers  # noqa: E402

KEY = Path(sys.argv[1])
OUT = Path(sys.argv[2])


def main() -> int:
    key = json.loads(KEY.read_text(encoding="utf-8"))
    findings = detect(OUT / "index.jsonl", OUT / "vault", extended=True)

    reported: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        reported[finding["path"].split("/")[-1].split(".")[0]] |= set(finding["value_hashes"])

    docs = {f["path"].split("/")[-1].split(".")[0]: f["path"] for f in findings}
    no_finding = Counter()
    cause: Counter[str] = Counter()
    by_cat: Counter[str] = Counter()

    for item in key["items"]:
        if item["kind"] != "phi":
            continue
        doc = item["doc"]
        hashes = reported.get(doc, set())
        if any(digest(f) in hashes for f in
               [item["value"], *(item.get("alt") or [])] if f):
            continue
        by_cat[item["cat"]] += 1
        if doc not in reported:
            no_finding[doc] += 1
            cause["document produced no finding at all"] += 1
        else:
            cause["finding exists, this identifier not in its hashes"] += 1

    print("missed by cause:")
    for name, count in cause.most_common():
        print(f"   {count:4}  {name}")
    print()
    print("documents that produced NO finding, and how many PHI items they hide:")
    for doc, count in no_finding.most_common():
        print(f"   {doc:<24} {count}")
    print()
    print("missed by category:")
    for name, count in by_cat.most_common(20):
        print(f"   {name:<26} {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
