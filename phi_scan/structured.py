"""Read structured clinical records as fields, not as text.

The failure a blind exam exposed: we parsed HL7, X12, DICOM and CSV, then
flattened every record into a blob of text and threw the labels away.
`DOE^JANE^Q` and `00012345` arrived as anonymous strings, and a text scanner
cannot tell a patient name from a test name.

So each format is read into labelled fields here:

    name=DOE^JANE^Q
    mrn=00012345
    dob=19941102
    ssn=521770943

The label is the evidence. No guessing, no model, no regex over prose.

Everything is returned as (label, value) pairs. Offsets are deliberately absent:
these are derived records, and the finding points at the whole record.
"""

from __future__ import annotations

# label -> what it is. Kept small and explicit so a reviewer can check it.
FIELDS = {
    "name", "provider", "mrn", "member", "accession", "ssn", "dob",
    "phone", "email", "address", "city", "zip", "license", "vehicle",
    "device", "url", "employer",
}


def render(pairs: list[tuple[str, str]]) -> str:
    """Canonical text form. detect.py parses this back into fields."""
    return "\n".join(f"{label}={value}" for label, value in pairs
                     if value and value.strip())


def _clean(value: str) -> str:
    return " ".join(value.replace("\x00", " ").split()).strip(" ^~*|")


# --------------------------------------------------------------------- HL7
# v2 is field-positional: PID-5 is the name, PID-7 the date of birth. The
# position is the label.
HL7_MAP = {
    3: "mrn",        # patient identifier list
    5: "name",       # patient name
    7: "dob",
    11: "address",
    13: "phone",
    19: "ssn",
}


def hl7_records(text: str) -> list[list[tuple[str, str]]]:
    records: list[list[tuple[str, str]]] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = line.strip("\x0b\x1c\x0d")
        if len(line) < 4 or line[:3] != "PID":
            continue
        fields = line.split("|")
        pairs: list[tuple[str, str]] = []
        for index, label in HL7_MAP.items():
            if index >= len(fields):
                continue
            raw = fields[index].split("~")[0]
            if not raw:
                continue
            if label == "mrn":
                raw = raw.split("^")[0]
            if label == "address":
                parts = raw.split("^")
                pairs.append(("address", _clean(parts[0])))
                if len(parts) > 2:
                    pairs.append(("city", _clean(parts[2])))
                if len(parts) > 4:
                    pairs.append(("zip", _clean(parts[4])))
                continue
            pairs.append((label, _clean(raw)))
        if pairs:
            records.append(pairs)
    return records


# --------------------------------------------------------------------- X12
# 837 claims: NM1 carries names, DMG the demographics, REF the member id.
def x12_records(text: str) -> list[list[tuple[str, str]]]:
    segments = [s.strip() for s in text.replace("\r", "").replace("\n", "").split("~") if s.strip()]
    pairs: list[tuple[str, str]] = []
    for segment in segments:
        parts = segment.split("*")
        tag = parts[0]
        if tag == "NM1" and len(parts) > 3:
            entity = parts[1] if len(parts) > 1 else ""
            last, first = _clean(parts[3]), _clean(parts[4]) if len(parts) > 4 else ""
            label = "provider" if entity in ("82", "85", "71", "72") else "name"
            if last or first:
                pairs.append((label, f"{last} {first}".strip()))
        elif tag == "DMG" and len(parts) > 2:
            pairs.append(("dob", _clean(parts[2])))
        elif tag == "REF" and len(parts) > 2 and parts[1] in ("SY", "1L", "23"):
            pairs.append(("member", _clean(parts[2])))
        elif tag == "N3" and len(parts) > 1:
            pairs.append(("address", _clean(parts[1])))
        elif tag == "N4" and len(parts) > 1:
            pairs.append(("city", _clean(parts[1])))
            if len(parts) > 3:
                pairs.append(("zip", _clean(parts[3])))
    return [pairs] if pairs else []


# --------------------------------------------------------------------- CSV
# The header row is the label. A column called "patient" holds a name; a column
# called "test" does not.
CSV_LABELS = {
    "name": "name", "patient": "name", "patientname": "name", "fullname": "name",
    "firstname": "name", "lastname": "name", "member": "name", "membername": "name",
    "subscriber": "name", "mrn": "mrn", "patientid": "mrn", "subjectid": "mrn",
    "suid": "mrn", "record": "mrn", "claim": "mrn", "account": "mrn",
    "dob": "dob", "birthdate": "dob", "dateofbirth": "dob",
    "ssn": "ssn", "social": "ssn",
    "phone": "phone", "mobile": "phone", "telephone": "phone",
    "email": "email",
    "address": "address", "street": "address",
    "city": "city", "zip": "zip", "zipcode": "zip", "postal": "zip",
    "provider": "provider", "physician": "provider",
}


def _label_for(header: str) -> str | None:
    key = "".join(ch for ch in header.lower() if ch.isalnum())
    return CSV_LABELS.get(key)


def csv_records(text: str) -> list[list[tuple[str, str]]]:
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) < 2:
        return []
    header = [h.strip().strip('"') for h in lines[0].split(",")]
    labels = [_label_for(h) for h in header]
    if not any(labels):
        return []
    records: list[list[tuple[str, str]]] = []
    for line in lines[1:]:
        cells = [c.strip().strip('"') for c in line.split(",")]
        pairs = [(label, cell) for label, cell in zip(labels, cells)
                 if label and cell and cell.lower() not in ("", "null", "none", "n/a")]
        if pairs:
            records.append(pairs)
    return records


# ------------------------------------------------------------------- DICOM
# The tag number is the label: (0010,0010) is PatientName by standard.
DICOM_MAP = {
    "0010,0010": "name",
    "0010,0020": "mrn",
    "0010,0030": "dob",
    "0010,1040": "address",
    "0010,2154": "phone",
    "0008,0090": "provider",
    "0008,0080": "employer",
    "0010,4000": "name",
    "0008,0050": "accession",
    "0018,1000": "device",
    "0020,4000": "name",
}


def dicom_records(tags: list[tuple[str, str]]) -> list[list[tuple[str, str]]]:
    pairs: list[tuple[str, str]] = []
    for tag, value in tags:
        label = DICOM_MAP.get(tag)
        if label is None and tag.startswith("0011"):
            # Private tags are where vendors park a second copy of the name.
            label = "name" if any(ch.isupper() for ch in value) else None
        if label and value.strip():
            pairs.append((label, _clean(value)))
    return [pairs] if pairs else []


def records_for(path: str, text: str) -> list[list[tuple[str, str]]]:
    if path.endswith(".hl7"):
        return hl7_records(text)
    if path.endswith(".x12"):
        return x12_records(text)
    if path.endswith(".csv"):
        return csv_records(text)
    return []
