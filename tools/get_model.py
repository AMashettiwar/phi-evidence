#!/usr/bin/env python3
"""Download a spaCy model wheel straight from GitHub and unzip it.

`python -m spacy download` shells out to pip, which has stalled twice in this
sandbox. A model wheel is pure Python plus data, so unzipping it into the target
folder is equivalent and does not need pip at all.

Run:  python tools/get_model.py en_core_web_sm-3.8.0
"""

from __future__ import annotations

import io
import sys
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "pylibs"
BASE = "https://github.com/explosion/spacy-models/releases/download"


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: get_model.py <model-version>   e.g. en_core_web_sm-3.8.0")
        return 2

    model = sys.argv[1]
    wheel = f"{model}-py3-none-any.whl"
    url = f"{BASE}/{model}/{urllib.parse.quote(wheel)}"

    print(f"fetching {url}")
    try:
        data = urllib.request.urlopen(url, timeout=180).read()
    except Exception as exc:  # noqa: BLE001
        print(f"download failed: {type(exc).__name__}: {exc}")
        return 1

    TARGET.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        archive.extractall(TARGET)

    print(f"installed {model}: {len(data)} bytes -> {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
