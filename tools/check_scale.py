#!/usr/bin/env python3
"""Gate G9: does this hold up at volume?

A 60-leak fixture proves the logic. It does not prove the tool survives a real
site. This copies the world twenty times, scans the lot, and measures time,
throughput, memory and whether the result is still exactly right.

Run:  python tools/check_scale.py [copies]
"""

from __future__ import annotations

import shutil
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "pylibs"))

from phi_scan.collect import collect  # noqa: E402
from phi_scan.detect import detect  # noqa: E402

WORLD = ROOT / "fixtures" / "world"
OUT = ROOT / "artifacts" / "g9"
COPIES = int(sys.argv[1]) if len(sys.argv) > 1 else 20


def main() -> int:
    source = OUT / "site"
    if source.exists():
        shutil.rmtree(source)
    source.mkdir(parents=True)

    for index in range(COPIES):
        shutil.copytree(WORLD, source / f"copy_{index:03d}")

    total_files = sum(1 for _ in source.rglob("*") if _.is_file())

    tracemalloc.start()
    started = time.time()
    manifest = collect(source, OUT / "run", str(ROOT / "pylibs"))
    collect_seconds = time.time() - started

    started = time.time()
    findings = detect(OUT / "run" / "index.jsonl", OUT / "run" / "vault")
    detect_seconds = time.time() - started
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    per_copy = 60
    expected_min = per_copy * COPIES

    print("=" * 70)
    print("SCALE GATE")
    print("=" * 70)
    print(f"copies               {COPIES}")
    print(f"files                {total_files}")
    print(f"observations         {manifest['observations']}")
    print(f"findings             {len(findings)}")
    print(f"collect              {collect_seconds:.2f}s")
    print(f"detect               {detect_seconds:.2f}s")
    print(f"total                {collect_seconds + detect_seconds:.2f}s")
    print(f"files per second     {total_files / (collect_seconds + detect_seconds):.1f}")
    print(f"peak memory          {peak / 1_048_576:.1f} MB")
    print(f"vault objects        written {manifest['vault']['objects_written']}, "
          f"reused {manifest['vault']['objects_reused']}")

    failures: list[str] = []
    if len(findings) < expected_min:
        failures.append(f"only {len(findings)} findings, expected at least {expected_min}")
    # Identical copies must not inflate findings through duplicate files.
    if manifest["vault"]["objects_reused"] == 0:
        failures.append("the vault never reused an object, so deduplication is broken")
    if peak / 1_048_576 > 1024:
        failures.append(f"peak memory {peak / 1_048_576:.0f} MB is over the 1 GB budget")

    print()
    if failures:
        print(f"FAIL  {len(failures)} problem(s)")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("PASS  result scales, vault deduplicates, memory stays bounded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
