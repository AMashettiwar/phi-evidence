#!/usr/bin/env python3
"""Prove the generated DICOM is a real DICOM file, using pydicom rather than our own reader.

A fixture that only our parser understands is worthless. This checks the file
with an independent implementation.

Run:  python tools/validate_dicom.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DICOM = ROOT / "fixtures" / "world" / "site" / "dicom" / "study.dcm"


def main() -> int:
    import pydicom  # noqa: PLC0415

    if not DICOM.exists():
        print(f"missing {DICOM}; run fixtures/build_world.py")
        return 2

    dataset = pydicom.dcmread(str(DICOM))
    print(f"pydicom {pydicom.__version__} read the file")
    print(f"  PatientName   {dataset.PatientName}")
    print(f"  PatientID     {dataset.PatientID}")
    print(f"  BirthDate     {dataset.PatientBirthDate}")
    print(f"  StudyDate     {dataset.StudyDate}")
    print(f"  StudyDesc     {dataset.StudyDescription}")
    print(f"  AdmittingDx   {dataset.AdmittingDiagnosesDescription}")
    print(f"  TransferSyntax {dataset.file_meta.TransferSyntaxUID}")
    print("PASS  the file is a valid DICOM Part 10 object")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
