#!/usr/bin/env python3
"""Prove the policy checker actually catches mistakes.

A check that always passes is worthless. This breaks the files on purpose,
seven different ways, and confirms the checker rejects each one. Everything is
restored at the end and hashes are compared to the originals.

Files are handled as raw bytes: text mode on Windows silently rewrites line
endings, which made an earlier version of this script report a false failure.

Run:  python tools/selftest_policy.py
Exit 0 means every deliberate mistake was caught and every file was restored.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import lint_policy  # noqa: E402

ID_PATH = ROOT / "policy" / "identifiers.yaml"
RULE_PATH = ROOT / "policy" / "rules.yaml"
SEV_PATH = ROOT / "policy" / "severity.yaml"

CASES = [
    ("identifier citation letter Z", ID_PATH,
     b'citation: "164.514(b)(2)(i)(R)"', b'citation: "164.514(b)(2)(i)(Z)"'),
    ("always-flag removed", ID_PATH,
     b"always_flag: true", b"always_flag: false"),
    ("duplicate identifier key", ID_PATH,
     b"key: vehicle", b"key: phone"),
    ("duplicate rule id", RULE_PATH,
     b"id: gina", b"id: phi_definition"),
    ("quote status flipped", RULE_PATH,
     b"quote_status: verified", b"quote_status: pending"),
    ("quote wording altered", RULE_PATH,
     b"Standard: Transmission security", b"Standard: Transmission Security"),
    ("address made critical", SEV_PATH,
     b"geography: medium", b"geography: critical"),
]


def run_check() -> tuple[int, str]:
    lint_policy.errors.clear()
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = lint_policy.main()
    return code, buffer.getvalue()


def first_error(output: str) -> str:
    for line in output.splitlines():
        if line.strip().startswith("- "):
            return line.strip()
    return "(no reason printed)"


def main() -> int:
    paths = (ID_PATH, RULE_PATH, SEV_PATH)
    originals = {p: p.read_bytes() for p in paths}
    before = {p: hashlib.sha256(b).hexdigest()[:16] for p, b in originals.items()}
    failures: list[str] = []

    print(f"identifiers.yaml sha256 {before[ID_PATH]}")
    print(f"rules.yaml       sha256 {before[RULE_PATH]}")
    print(f"severity.yaml    sha256 {before[SEV_PATH]}")

    try:
        code, _ = run_check()
        if code != 0:
            print("SETUP FAIL: unmodified files do not pass")
            return 1
        print("baseline (no changes)            -> pass, as expected")

        for name, path, old, new in CASES:
            source = originals[path]
            if old not in source:
                failures.append(f"{name}: test pattern not found")
                print(f"{name:32} -> PATTERN MISSING")
                continue
            path.write_bytes(source.replace(old, new))
            code, output = run_check()
            if code == 0:
                failures.append(f"{name}: NOT CAUGHT")
                print(f"{name:32} -> MISSED")
            else:
                print(f"{name:32} -> caught  {first_error(output)}")
            path.write_bytes(source)
    finally:
        for path, source in originals.items():
            path.write_bytes(source)

    print("-" * 70)
    after = {p: hashlib.sha256(p.read_bytes()).hexdigest()[:16] for p in paths}
    restored = after == before
    print(f"files restored to original bytes: {restored}")
    if not restored:
        for p in paths:
            print(f"  {p.name}: {before[p]} -> {after[p]}")
        failures.append("files were not restored")

    if failures:
        print(f"FAIL  {len(failures)} problem(s)")
        for item in failures:
            print(f"  - {item}")
        return 1

    print(f"PASS  {len(CASES)} deliberate mistakes, {len(CASES)} caught, files unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
