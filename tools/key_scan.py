#!/usr/bin/env python3
"""Key-anchored scan: find identifier fields by the JSON key they sit under.

Name detection on structured clinical data does not converge, because every
field label is a capitalised pair. The keys, however, are exact: a value under
`patientName` is a patient name; a value under `testName` is not.

No model, no regex guessing. Reports counts and masked examples only.

Run:  python tools/key_scan.py <file.har>
"""

from __future__ import annotations

import base64
import json
import re
import sys
import urllib.parse
from collections import Counter, defaultdict
from pathlib import Path

PATTERNS = {
    # Snake_case and camelCase both appear in real schemas, and the first
    # version of this file only handled camelCase. It reported 4 fields on a
    # response that held 10 full subject records.
    "patient name": re.compile(
        r"^(patient|pt|subject)[_ ]?(full|first|last|middle)?[_ ]?name$"
        r"|^(first|last|middle|full|sur)[_ ]?name$", re.I),
    "record number": re.compile(
        r"^(mrn|uhid|patient[_ ]?id|subject[_ ]?id|subjectid|suid|accession[_ ]?(number|id)?"
        r"|sample[_ ]?id|specimen[_ ]?id)$", re.I),
    "date of birth": re.compile(
        r"^(dob|date[_ ]?of[_ ]?birth|birth[_ ]?date|birthdate)$", re.I),
    "ssn": re.compile(r"^(ssn|socialsecurity(number)?)$", re.I),
    "phone": re.compile(
        r"^(phone|mobile|alternate[_ ]?number|contact[_ ]?number"
        r"|emergency[_ ]?contact[_ ]?number|phone[_ ]?number)$", re.I),
    "email": re.compile(r"^(email|email[_ ]?id|emailaddress|email[_ ]?address)$", re.I),
    "address": re.compile(
        r"^(address|street|city|state|zip|zipcode|postal[_ ]?code|pincode"
        r"|country|country[_ ]?code)$", re.I),
    "insurance": re.compile(r"^(insurance|policynumber|memberid|planid)$", re.I),
    "diagnosis": re.compile(
        r"^(cancer[_ ]?site|date[_ ]?of[_ ]?initial[_ ]?diagnosis|diagnosis"
        r"|icd[_ ]?10|stage|tumou?r[_ ]?type)$", re.I),
    "genomic": re.compile(
        r"^(normal[_ ]?fastq[_ ]?file[_ ]?r[12]|normal[_ ]?sequencer[_ ]?sample[_ ]?id"
        r"|fastq|bam|vcf)$", re.I),
    "demographic": re.compile(r"^(gender|sex|age|marital[_ ]?status|nationality)$", re.I),
}


def mask(value: str) -> str:
    value = str(value)
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]


def main() -> int:
    har = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    hits: dict[str, list[str]] = defaultdict(list)
    by_path: Counter[tuple[str, str]] = Counter()
    documents = 0

    for entry in har["log"]["entries"]:
        content = entry["response"].get("content", {}) or {}
        text = content.get("text") or ""
        mime = (content.get("mimeType") or "").lower()
        if "json" not in mime or not text:
            continue
        if content.get("encoding") == "base64":
            text = base64.b64decode(text).decode("utf-8", "replace")
        try:
            payload = json.loads(text)
        except Exception:  # noqa: BLE001
            continue
        documents += 1
        path = urllib.parse.urlparse(entry["request"]["url"]).path
        # The GraphQL operation name is schema, not patient data, and it tells
        # us which call returns the records.
        operation = ""
        post = (entry["request"].get("postData") or {}).get("text") or ""
        match = re.search(r'"operationName"\s*:\s*"([^"]+)"', post)
        if match:
            operation = match.group(1)
        elif post.strip().startswith("query"):
            found = re.match(r"\s*query\s+(\w+)", post)
            operation = found.group(1) if found else "query"
        label_path = f"{path} {operation}".strip()

        def walk(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    if isinstance(value, (str, int)) and not isinstance(value, bool):
                        for label, pattern in PATTERNS.items():
                            if pattern.match(key):
                                text_value = str(value).strip()
                                if text_value and text_value.lower() not in ("null", "none", "na", "n/a", "-"):
                                    hits[label].append(text_value)
                                    by_path[(label_path, label)] += 1
                    else:
                        walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(payload)

    print(f"json documents      {documents}")
    print(f"identifier fields   {sum(len(v) for v in hits.values())}")
    print()
    for label in sorted(hits):
        values = hits[label]
        distinct = len(set(values))
        print(f"  {label:14} {len(values):5} values, {distinct:4} distinct   "
              f"example {mask(values[0])}")
    print()
    for (path, label), count in by_path.most_common(12):
        print(f"  {path:40} {label:14} {count}")
    if not hits:
        print("  no identifier fields found under any recognised key")
    print("\nNothing was printed in the clear. Nothing was written to disk.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
