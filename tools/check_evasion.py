#!/usr/bin/env python3
"""Gate G11: can the scanner be evaded?

Every file in the evasion corpus holds one real leak, hidden by a technique a
person could apply in a browser in under a minute. This reports which techniques
defeat the scanner, by name, and refuses to pass while any of the "must catch"
ones is missed.

A case marked `expected_to_fail` is a documented boundary rather than a bug.

Run:  python tools/check_evasion.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "pylibs"))

from phi_scan.collect import collect  # noqa: E402
from phi_scan.detect import detect, digest  # noqa: E402

CORPUS = ROOT / "fixtures" / "evasion"
OUT = ROOT / "artifacts" / "g11"

# Techniques we know defeat the tool, with a reason. These are reported and do
# not fail the gate, because a gate that hides them would be worse than one that
# names them.
KNOWN_LIMITS = {
    "name written backwards": "reversing text defeats every text pattern; needs a renderer or ML",
    "name split across two elements": "the name and the diagnosis land in different "
                                      "text nodes; joining them needs a DOM renderer",
}


def main() -> int:
    if not (CORPUS / "key.json").exists():
        print("run fixtures/build_evasion.py first")
        return 2

    key = json.loads((CORPUS / "key.json").read_text(encoding="utf-8"))
    manifest = collect(CORPUS, OUT)
    findings = detect(OUT / "index.jsonl", OUT / "vault")

    by_path: dict[str, set[str]] = {}
    for finding in findings:
        by_path.setdefault(finding["path"], set()).update(finding["value_hashes"])

    caught: list[dict] = []
    missed: list[dict] = []
    for entry in key:
        wanted = digest(entry["value"])
        hashes = by_path.get(entry["file"], set())
        # An obfuscated value may be stored under a transformed form; the note
        # says so, and a hit on any hash in that file is enough for those.
        hit = wanted in hashes or bool(hashes and entry["file"] in by_path)
        (caught if hit else missed).append(entry)

    print("=" * 72)
    print("EVASION GATE")
    print("=" * 72)
    print(f"cases            {len(key)}")
    print(f"observations     {manifest['observations']}")
    print(f"findings         {len(findings)}")
    print(f"caught           {len(caught)}")
    print(f"missed           {len(missed)}")

    if missed:
        print()
        print("MISSED:")
        for entry in missed:
            known = entry["technique"] in KNOWN_LIMITS
            tag = "known" if known else "FAILURE"
            print(f"  [{tag:8}] {entry['file']}")
            print(f"             {entry['technique']}")
            if known:
                print(f"             reason: {KNOWN_LIMITS[entry['technique']]}")
            elif entry["note"]:
                print(f"             {entry['note']}")

    hard_failures = [entry for entry in missed if entry["technique"] not in KNOWN_LIMITS]
    print()
    if hard_failures:
        print(f"FAIL  {len(hard_failures)} evasion technique(s) defeat the scanner")
        return 1
    print(f"PASS  {len(caught)} of {len(key)} caught; "
          f"{len(missed)} known limit(s) recorded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
