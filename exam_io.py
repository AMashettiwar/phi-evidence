"""Zip extraction for the UI. No Streamlit import, so it can be tested."""

from __future__ import annotations

import zipfile
from pathlib import Path


def extract(archive: zipfile.ZipFile, target: Path) -> int:
    """Extract a zip safely. Returns how many files were written."""
    written = 0
    root = target.resolve()
    for member in archive.infolist():
        name = member.filename
        if name.startswith("__MACOSX") or name.endswith("/"):
            continue
        path = (target / name).resolve()
        if not str(path).startswith(str(root)):
            continue  # zip-slip
        path.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(member) as source, open(path, "wb") as sink:
            sink.write(source.read())
        written += 1
    return written
