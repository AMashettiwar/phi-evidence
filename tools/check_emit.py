#!/usr/bin/env python3
"""Gate: redact with our own spans, rescan, and require zero findings.

This is the only test that proves the positions are real. If an offset is
cosmetic, the rescan finds the leak again and the gate fails.

Run:  python tools/check_emit.py
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "pylibs"))

from phi_scan.collect import collect  # noqa: E402
from phi_scan.detect import detect  # noqa: E402
from phi_scan.positions import write_findings, write_redacted  # noqa: E402

WORLD = ROOT / "fixtures" / "world"
OUT = ROOT / "artifacts" / "emit"


def main() -> int:
    if not WORLD.exists():
        print("run fixtures/build_world.py first")
        return 2
    if OUT.exists():
        shutil.rmtree(OUT)

    collect(WORLD, OUT / "run")
    findings = detect(OUT / "run" / "index.jsonl", OUT / "run" / "vault",
                      context="covered-entity")

    count = write_findings(findings, OUT / "run" / "index.jsonl",
                           OUT / "run" / "vault", OUT / "findings.jsonl")
    lines = [json.loads(line) for line in
             (OUT / "findings.jsonl").read_text(encoding="utf-8").splitlines() if line]
    positioned = [line for line in lines if "start" in line or "text" in line]
    verdicts = [line for line in lines if line.get("has_phi")]

    redacted = write_redacted(findings, WORLD, OUT / "redacted")
    collect(OUT / "redacted", OUT / "recheck")
    again = detect(OUT / "recheck" / "index.jsonl", OUT / "recheck" / "vault",
                   context="covered-entity")

    print("=" * 68)
    print("POSITIONAL OUTPUT GATE")
    print("=" * 68)
    print(f"findings             {len(findings)}")
    print(f"positional lines     {len(positioned)}  (expected {count})")
    print(f"document verdicts    {len(verdicts)}")
    print(f"redacted files       {redacted}")
    print(f"findings after rescan {len(again)}")

    failures: list[str] = []
    if len(positioned) != count:
        failures.append("positional line count does not match the finding count")
    if not verdicts:
        failures.append("no document verdicts emitted")
    if again:
        failures.append(f"{len(again)} finding(s) survive redaction; spans are not real")

    if failures:
        print()
        print(f"FAIL  {len(failures)} problem(s)")
        for problem in failures:
            print(f"   {problem}")
        return 1
    print()
    print("PASS  every finding is positioned, and redaction removes every one")
    return 0


if __name__ == "__main__":
    sys.exit(main())
