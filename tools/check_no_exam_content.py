#!/usr/bin/env python3
"""Fail if any value from a sealed answer key appears anywhere in this repository.

This is the guard that keeps a scored result from leaking into the product. Run it
in CI with the key supplied as a secret, never committed:

    python tools/check_no_exam_content.py --key /path/to/key.json

With no key supplied the check still runs a structural sweep for the one thing
that must never appear in a public repository: anything under a sealed/ directory.

The tool prints counts only. It never echoes a key value, so running it cannot
leak what it is protecting.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", "__pycache__", "pylibs", "artifacts", "fixtures/world",
             "fixtures/evasion", "fixtures/context", "node_modules", ".venv"}
TEXT_SUFFIXES = {".py", ".md", ".yaml", ".yml", ".json", ".txt", ".toml", ".cfg",
                 ".ini", ".html", ".csv", ".sh", ".ps1"}
TOKEN = re.compile(r"[^\W_]{6,}", re.UNICODE)


def iter_files():
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        if any(rel.startswith(skip) or f"/{skip}/" in f"/{rel}" for skip in SKIP_DIRS):
            continue
        if "sealed/" in f"/{rel}":
            yield path, rel, True
            continue
        if path.suffix.lower() in TEXT_SUFFIXES:
            yield path, rel, False


def key_values(key_path: Path) -> set[str]:
    """Distinctive strings from the key: values and alternates, normalised.

    Coincidences are excluded on purpose. A synthetic date of birth will collide
    with a date in any key, and "example.org" collides with every synthetic
    fixture ever written. Flagging those would make the guard cry wolf until
    somebody turned it off, which is worse than a slightly narrower check.
    """
    data = json.loads(key_path.read_text(encoding="utf-8"))
    values: set[str] = set()
    for item in data.get("items", []):
        for field in ("value", *(item.get("alt") or [])):
            if not isinstance(field, str):
                continue
            normalised = "".join(ch.lower() for ch in field if ch.isalnum())
            if len(normalised) < 10:
                continue            # short numbers and initials collide by chance
            if normalised.isdigit():
                continue            # a date or a record number is not distinctive
            if "example" in normalised:
                continue            # reserved documentation domain
            values.add(normalised)
    return values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", default=None,
                        help="answer key JSON; omit to run the structural sweep only")
    args = parser.parse_args()

    problems: list[str] = []
    wanted = key_values(Path(args.key)) if args.key else set()
    scanned = 0

    for path, rel, sealed in iter_files():
        if sealed:
            problems.append(f"{rel}: file lives under sealed/ and must not be committed")
            continue
        scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not wanted:
            continue
        normalised = "".join(ch.lower() for ch in text if ch.isalnum())
        hits = sum(1 for value in wanted if value in normalised)
        if hits:
            problems.append(f"{rel}: contains {hits} value(s) from the answer key")

    print(f"files scanned        {scanned}")
    print(f"key values checked   {len(wanted) if wanted else 'none (structural sweep only)'}")
    if problems:
        print(f"FAIL  {len(problems)} problem(s)")
        for problem in problems:
            print(f"   {problem}")
        return 1
    print("PASS  no key value and no sealed artefact in the repository")
    return 0


if __name__ == "__main__":
    sys.exit(main())
