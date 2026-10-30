#!/usr/bin/env python3
"""For every missed PHI item, is the value even in the text we captured?

Splits the remaining misses into two honest classes:
  present  - the document contains the value; our detectors did not recognise it
  absent   - the value is transformed (encoded, split, spelled, pixels), so no
             detector operating on this text could see it as-is
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "pylibs"))

from phi_scan.detect import detect, digest  # noqa: E402
from phi_scan.vault import Vault  # noqa: E402


def main() -> int:
    key = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    out = Path(sys.argv[2])
    findings = detect(out / "index.jsonl", out / "vault", extended=True)
    vault = Vault(out / "vault")
    rows = [json.loads(line) for line in
            (out / "index.jsonl").read_text(encoding="utf-8").splitlines() if line]

    doc_text: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        doc_id = row["path"].split("/")[-1].split(".")[0]
        try:
            doc_text[doc_id].append(vault.get(row["doc"]).decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            continue

    reported: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        doc_id = finding["path"].split("/")[-1].split(".")[0]
        reported[doc_id] |= set(finding["value_hashes"])

    present = Counter()
    absent = Counter()
    examples: dict[str, int] = Counter()
    for item in key["items"]:
        if item["kind"] != "phi":
            continue
        doc = item["doc"]
        hashes = reported.get(doc, set())
        forms = [item["value"], *(item.get("alt") or [])]
        if any(digest(f) in hashes for f in forms if f):
            continue
        blob = "\n".join(doc_text.get(doc, []))
        if any(f and f in blob for f in forms):
            present[item["cat"]] += 1
        else:
            absent[item["cat"]] += 1
            examples[item["layer"]] += 1

    print(f"missed but PRESENT in captured text : {sum(present.values())}")
    print(f"missed and ABSENT (transformed)     : {sum(absent.values())}")
    print()
    print("present but not recognised, by category:")
    for name, count in present.most_common(15):
        print(f"   {name:<26} {count}")
    print()
    print("absent, by layer:")
    for name, count in examples.most_common():
        print(f"   {name:<26} {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
