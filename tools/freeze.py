#!/usr/bin/env python3
"""Record the answer-key hashes in eval/frozen.json, which is committed.

Freezing is a deliberate act with a visible diff. The generators never write
this file, so changing a fixture after the freeze makes check_world and gate_g1
fail until someone re-freezes on purpose and the commit says why.

Run:  python tools/freeze.py
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEYS = ROOT / "eval" / "keys"


def sha256(path: Path) -> str:
    """Over LF line endings: git may check a text file out with CRLF on Windows
    and LF elsewhere, and the freeze must not depend on that."""
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def main() -> int:
    record = {
        "world_key_sha256": sha256(KEYS / "world_key.json"),
        "corpus_key_sha256": sha256(KEYS / "corpus_key.json"),
        "protocol_sha256": sha256(ROOT / "eval" / "protocol.md"),
        "frozen_on": date.today().isoformat(),
        "generators_at_commit": subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(),
        "note": "Frozen before the first scored run. Any change to a key invalidates every score.",
    }
    (ROOT / "eval" / "frozen.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
