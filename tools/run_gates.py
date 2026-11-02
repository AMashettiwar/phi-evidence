#!/usr/bin/env python3
"""Run every gate in order and fail if any one fails.

This list is the only list. TESTING.md, the README and CI all point here, so
what is documented is what runs.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

GATES = [
    ["-m", "pytest", "-q", "tests"],
    ["fixtures/build_world.py"],
    ["tools/check_world.py"],
    ["tools/check_collect.py"],
    ["tools/check_detect.py"],
    ["fixtures/build_injection.py"],
    ["tools/check_ai.py"],
    ["tools/check_crawl.py"],
    ["tools/check_scale.py"],
    ["tools/lint_policy.py"],
    ["fixtures/build_evasion.py"],
    ["tools/check_evasion.py"],
    ["fixtures/build_context.py"],
    ["tools/check_context.py"],
    ["tools/check_emit.py"],
    ["tools/check_no_exam_content.py"],
]


def main() -> int:
    failed = []
    for gate in GATES:
        name = " ".join(gate)
        began = time.monotonic()
        result = subprocess.run([sys.executable, *gate], cwd=ROOT, capture_output=True,
                                text=True, encoding="utf-8", errors="replace")
        seconds = time.monotonic() - began
        status = "PASS" if result.returncode == 0 else "FAIL"
        print(f"{status}  {seconds:6.1f}s  {name}")
        if result.returncode != 0:
            failed.append(name)
            tail = (result.stdout + result.stderr).strip().splitlines()[-15:]
            print("\n".join(f"        {line}" for line in tail))
    print(f"\n{len(GATES) - len(failed)}/{len(GATES)} gates passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
