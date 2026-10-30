#!/usr/bin/env python3
"""G4: does every document in the exam produce at least one finding?"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "pylibs"))

from phi_scan.detect import detect  # noqa: E402

EXAM = Path("C:/Users/Ankith Mashettiwar/AppData/Local/Temp/dsh-OOmNGe/phi-exam/src/phi-exam")
OUT = ROOT / "artifacts" / "exam-final"


def main() -> int:
    findings = detect(OUT / "index.jsonl", OUT / "vault", extended=True)
    covered = {f["path"].split("/")[-1].split(".")[0] for f in findings}
    total = sorted(p.stem.split(".")[0] for p in EXAM.rglob("*") if p.is_file())
    missing = [name for name in total if name.split("_")[0] not in covered
               and name not in covered]
    print(f"documents        {len(total)}")
    print(f"with a finding   {len(total) - len(missing)}/{len(total)}")
    if missing:
        print("with none:       " + ", ".join(sorted(missing)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
