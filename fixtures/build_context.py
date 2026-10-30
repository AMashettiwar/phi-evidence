#!/usr/bin/env python3
"""Build two fixtures that separate the two contexts.

A log line holding only a record number and an e-mail address, and a roster
holding only names and dates of birth. Neither carries a health fact.

Under covered-entity both are exposures. Under public-web neither is. If the
tool reports them the same way in both contexts, `--context` is not doing
anything and the gate fails.

Run:  python fixtures/build_context.py
"""

from __future__ import annotations

from pathlib import Path

OUT = Path(__file__).resolve().parent / "context"

LOG = """\
2026-01-14T09:12:03Z INFO  lookup patient mrn=4471203 email=oscar.quillfeather@example.org
2026-01-14T09:12:07Z INFO  lookup patient mrn=4471203 email=oscar.quillfeather@example.org
2026-01-14T09:13:41Z INFO  export requested by operator for mrn=4471203
"""

ROSTER = """\
name,dob,ward
Nova Bramblewood,1936-02-14,3A
Kip Wrenfield,1940-05-05,3B
Ozzy Quillfeather,1977-11-02,4A
"""

# A control that must NOT fire in either context: no identifier at all.
CLEAN = """\
Operations summary for the week.

Three wards ran at 82% occupancy. Two maintenance windows were completed.
No incidents recorded.
"""


def main() -> int:
    if OUT.exists():
        import shutil
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    (OUT / "access.log").write_text(LOG, encoding="utf-8")
    (OUT / "roster.csv").write_text(ROSTER, encoding="utf-8")
    (OUT / "summary.txt").write_text(CLEAN, encoding="utf-8")

    print(f"wrote {len(list(OUT.iterdir()))} files to {OUT}")
    print("  access.log   record number and e-mail, no health fact")
    print("  roster.csv   names and dates of birth, no health fact")
    print("  summary.txt  control: no identifier, must stay silent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
