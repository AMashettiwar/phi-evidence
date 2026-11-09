#!/usr/bin/env python3
"""Fetch a pure-Python package straight from PyPI without using pip.

pip stalls in this sandbox for reasons that are not the network: plain urllib
downloads from the same host are fast. So we download the wheel and unzip it.

Run:  python tools/get_wheel.py <package> <target-dir>
"""

from __future__ import annotations

import io
import json
import sys
import urllib.request
import zipfile
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: get_wheel.py <package> <target-dir>")
        return 2

    package, target = sys.argv[1], Path(sys.argv[2])
    meta = json.load(urllib.request.urlopen(
        f"https://pypi.org/pypi/{package}/json", timeout=60))
    version = meta["info"]["version"]
    wheels = [u for u in meta["urls"] if u["filename"].endswith(".whl")]
    if not wheels:
        print(f"no wheel published for {package} {version}")
        return 1

    wheel = wheels[0]
    data = urllib.request.urlopen(wheel["url"], timeout=120).read()
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        archive.extractall(target)

    print(f"{package} {version}: {len(data)} bytes -> {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
