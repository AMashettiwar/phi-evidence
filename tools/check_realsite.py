#!/usr/bin/env python3
"""False alarms and misses on a realistic hospital website.

fixtures/build_realsite.py builds a site of the pages real health systems carry
(doctor bios, bylines, trial investigators, sample cards, the FHIR example
patient, real vendor libraries) plus planted leaks in those same pages. Scanned
as a public website:

  * every planted leak must be found (fixtures/realsite/key.json)
  * nothing else may be reported: any other finding is a false alarm

Exit code 0 only when both hold.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phi_scan.collect import collect  # noqa: E402
from phi_scan.detect import detect, digest  # noqa: E402

SITE = ROOT / "fixtures" / "realsite" / "site"
KEY = ROOT / "fixtures" / "realsite" / "key.json"


def main() -> int:
    subprocess.run([sys.executable, str(ROOT / "fixtures" / "build_realsite.py")], check=True)
    leaks = json.loads(KEY.read_text(encoding="utf-8"))["leaks"]
    with tempfile.TemporaryDirectory() as scratch:
        os.environ["PHI_EVIDENCE_KEYS"] = str(Path(scratch) / "keys")
        out = Path(scratch) / "out"
        collect(SITE, out)
        cleared: list[dict] = []
        findings = detect(out / "index.jsonl", out / "vault", (), context="public-web",
                          cleared=cleared)
        planted = {(leak["path"], digest(leak["value"])) for leak in leaks}
        found = {(leak["path"], digest(leak["value"])) for leak in leaks
                 for f in findings if f["path"] == leak["path"]
                 and digest(leak["value"]) in f["value_hashes"]}
        false = [f for f in findings
                 if not any((f["path"], h) in planted for h in f["value_hashes"])]

    print(f"findings          {len(findings)}")
    print(f"planted leaks     {len(found)}/{len(leaks)} found")
    for leak in leaks:
        if (leak["path"], digest(leak["value"])) not in found:
            print(f"  MISSED  {leak['path']}: {leak['why']}")
    print(f"false alarms      {len(false)}")
    for f in false:
        print(f"  {f['level']:8} {f['carrier']:14} {f['extraction']:22} {f['path']} "
              f"{f['identifiers']} {f['value_mask']}")
    print(f"cleared           {len(cleared)} with a stated reason")
    ok = len(found) == len(leaks) and not false
    print("PASS  every planted leak found, no false alarms on a realistic site" if ok
          else "FAIL  realistic site")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
