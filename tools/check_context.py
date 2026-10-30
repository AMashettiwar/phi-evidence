#!/usr/bin/env python3
"""Gate: --context changes the test, and both directions hold.

Requirement, from the brief:

    a log line with only an MRN and an email, and a roster with only names and
    dates of birth, are both reported in covered-entity and both suppressed in
    public-web.

A control file with no identifier must stay silent in both, so the gate cannot
pass by reporting everything.

Run:  python tools/check_context.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "pylibs"))

from phi_scan.collect import collect  # noqa: E402
from phi_scan.detect import detect  # noqa: E402

CORPUS = ROOT / "fixtures" / "context"
OUT = ROOT / "artifacts" / "context"


def names(findings: list[dict]) -> set[str]:
    return {f["path"].split("/")[-1] for f in findings}


def main() -> int:
    if not CORPUS.exists():
        print("run fixtures/build_context.py first")
        return 2

    collect(CORPUS, OUT)
    covered = detect(OUT / "index.jsonl", OUT / "vault", context="covered-entity")
    public = detect(OUT / "index.jsonl", OUT / "vault", context="public-web")

    covered_files = names(covered)
    public_files = names(public)

    print("=" * 68)
    print("CONTEXT GATE")
    print("=" * 68)
    print(f"covered-entity findings {len(covered):3}  files {sorted(covered_files)}")
    print(f"public-web     findings {len(public):3}  files {sorted(public_files)}")
    print()

    failures: list[str] = []
    for wanted in ("access.log", "roster.csv"):
        if wanted not in covered_files:
            failures.append(f"{wanted} not reported under covered-entity")
        if wanted in public_files:
            failures.append(f"{wanted} reported under public-web, must be suppressed")
    if "summary.txt" in covered_files or "summary.txt" in public_files:
        failures.append("summary.txt has no identifier but was reported")

    if failures:
        print(f"FAIL  {len(failures)} problem(s)")
        for problem in failures:
            print(f"   {problem}")
        return 1
    print("PASS  identifier-alone reported in covered-entity, suppressed in public-web")
    return 0


if __name__ == "__main__":
    sys.exit(main())
