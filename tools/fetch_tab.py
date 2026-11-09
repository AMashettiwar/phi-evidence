#!/usr/bin/env python3
"""Fetch the TAB ECHR splits.

dev  -> development. iterate freely here.
test -> measurement. run once, after development is finished.

Run:  python tools/fetch_tab.py
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "fixtures" / "public" / "tab"
UA = {"User-Agent": "phi-scan-research/0.1"}


def get(url: str) -> bytes:
    request = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(request, timeout=180) as response:
        return response.read()


def main() -> int:
    listing = json.loads(get(
        "https://api.github.com/repos/NorskRegnesentral/"
        "text-anonymization-benchmark/contents/"))
    entries = {item["name"]: item for item in listing if isinstance(item, dict)}
    print(f"files available: {', '.join(sorted(entries))}")

    OUT.mkdir(parents=True, exist_ok=True)
    for name in ("echr_dev.json", "echr_test.json"):
        if name not in entries:
            print(f"  {name}: not published in this repo")
            continue
        entry = entries[name]
        target = OUT / name
        if target.exists() and target.stat().st_size == entry["size"]:
            print(f"  {name}: already present")
            continue
        print(f"  {name}: downloading {entry['size']} bytes")
        target.write_bytes(get(entry["download_url"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
