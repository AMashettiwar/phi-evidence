#!/usr/bin/env python3
"""Check the test world and its answer key before anything is allowed to scan it.

This is the gate. It proves the answer key is honest: every planted value really
sits where the key says, exactly once, and every rule and level it cites exists
in the policy files.

Run:  python tools/check_world.py
      python tools/check_world.py --key path/to/other_key.json   (used to prove
                                                                  the check bites)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORLD = ROOT / "fixtures" / "world"
KEYS = ROOT / "eval" / "keys"
REQUIRED_CARRIERS = {
    # visible or plainly linked
    "page_text", "hidden_code", "url", "title", "browser_storage",
    "third_party", "api_response", "downloadable_file", "file_metadata",
    "error_surface", "log",
    # hidden tier: not readable by scrolling a page
    "meta_tag", "html_attribute", "css_hidden", "inline_script", "js_bundle",
    "encoded_value", "source_map", "sitemap", "unlinked_file", "env_file",
    # discovery surfaces and build leftovers
    "robots_txt", "git_exposure", "api_docs", "print_css",
    # clinical interchange formats
    "fhir_resource", "dicom_header",
}
MIN_FLAGGED = 60
MIN_CLEAN = 8

errors: list[str] = []


def load_policy() -> tuple[set[str], set[str], set[str]]:
    ids = yaml.safe_load((ROOT / "policy" / "identifiers.yaml").read_text(encoding="utf-8"))
    rules = yaml.safe_load((ROOT / "policy" / "rules.yaml").read_text(encoding="utf-8"))
    sev = yaml.safe_load((ROOT / "policy" / "severity.yaml").read_text(encoding="utf-8"))
    return (
        {r["key"] for r in ids["identifiers"]},
        {r["id"] for r in rules["rules"]},
        set(sev["meta"]["levels"]),
    )


def check_pdf(path: Path) -> list[str]:
    """Confirm the PDF xref points at real objects. A broken PDF is a broken test."""
    problems: list[str] = []
    data = path.read_bytes()
    if not data.startswith(b"%PDF-"):
        return [f"{path.name}: does not start with %PDF"]
    marker = data.rfind(b"startxref")
    if marker < 0:
        return [f"{path.name}: no startxref"]
    try:
        start = int(data[marker + len(b"startxref"):].split()[0])
    except (ValueError, IndexError):
        return [f"{path.name}: startxref is not a number"]
    if data[start:start + 4] != b"xref":
        return [f"{path.name}: startxref points at {data[start:start + 12]!r}, not at xref"]

    lines = data[start:].split(b"\n")
    try:
        _, count = lines[1].split()
        total = int(count)
    except (ValueError, IndexError):
        return [f"{path.name}: xref subsection header is malformed"]

    entries = lines[2:2 + total]
    if len(entries) != total:
        return [f"{path.name}: xref claims {total} entries but has {len(entries)}"]
    for number in range(1, total):
        try:
            offset = int(entries[number].split()[0])
        except (ValueError, IndexError):
            problems.append(f"{path.name}: xref entry {number} is malformed")
            continue
        expected = f"{number} 0 obj".encode()
        if data[offset:offset + len(expected)] != expected:
            problems.append(
                f"{path.name}: xref entry {number} points at {data[offset:offset + 10]!r}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", default=str(KEYS / "world_key.json"))
    args = parser.parse_args()
    key_path = Path(args.key)

    if not key_path.exists():
        print(f"FAIL answer key not found: {key_path}")
        return 1

    key_text = key_path.read_text(encoding="utf-8")
    key = json.loads(key_text)
    items = key.get("items") or []

    id_keys, rule_ids, levels = load_policy()

    # --- freeze check ------------------------------------------------------
    frozen_path = KEYS / "FROZEN.json"
    if key_path == KEYS / "world_key.json":
        if not frozen_path.exists():
            errors.append("FROZEN.json missing - the key was never frozen")
        else:
            frozen = json.loads(frozen_path.read_text(encoding="utf-8"))
            actual = hashlib.sha256(key_text.encode("utf-8")).hexdigest()
            if actual != frozen.get("world_key_sha256"):
                errors.append("answer key does not match the frozen hash - it changed after freezing")

    # --- volume ------------------------------------------------------------
    flagged = [i for i in items if i.get("expected_flag")]
    clean = [i for i in items if not i.get("expected_flag")]
    if len(flagged) < MIN_FLAGGED:
        errors.append(f"only {len(flagged)} planted leaks, need at least {MIN_FLAGGED}")
    if len(clean) < MIN_CLEAN:
        errors.append(f"only {len(clean)} clean items, need at least {MIN_CLEAN}")

    carriers = {i["carrier"] for i in flagged}
    missing = REQUIRED_CARRIERS - carriers
    if missing:
        errors.append(f"carriers with no planted leak: {sorted(missing)}")

    # --- every item --------------------------------------------------------
    seen_ids: set[str] = set()
    for item in items:
        tag = item.get("id", "<no id>")
        if tag in seen_ids:
            errors.append(f"{tag}: duplicate id")
        seen_ids.add(tag)

        path = WORLD / item["file"]
        if not path.exists():
            errors.append(f"{tag}: file missing {item['file']}")
            continue
        data = path.read_bytes()
        value = item["value"].encode("utf-8")
        count = data.count(value)
        offset = item.get("offset", -1)

        if count != 1:
            errors.append(f"{tag}: value appears {count} times, expected 1")
        if not (0 <= offset < len(data)):
            errors.append(f"{tag}: offset {offset} is outside the file")
        elif data[offset:offset + len(value)] != value:
            errors.append(f"{tag}: value is not at the recorded offset {offset}")

        if item.get("expected_flag"):
            if item.get("expected_level") not in levels:
                errors.append(f"{tag}: level '{item.get('expected_level')}' is not a policy level")
            unknown_ids = set(item.get("identifiers") or []) - id_keys
            if unknown_ids:
                errors.append(f"{tag}: identifiers not in the table: {sorted(unknown_ids)}")
            unknown_rules = set(item.get("rules") or []) - rule_ids
            if unknown_rules:
                errors.append(f"{tag}: rules not in the registry: {sorted(unknown_rules)}")
            if not item.get("rules"):
                errors.append(f"{tag}: every finding must cite at least one rule")
        else:
            if item.get("expected_level") in {"critical", "high"}:
                errors.append(f"{tag}: clean item rated {item['expected_level']}")

    # --- pdf integrity -----------------------------------------------------
    for pdf in sorted(WORLD.rglob("*.pdf")):
        errors.extend(check_pdf(pdf))

    # --- report ------------------------------------------------------------
    files = sorted({i["file"] for i in items})
    print("=" * 70)
    print("TEST WORLD CHECK")
    print("=" * 70)
    print(f"planted leaks   {len(flagged):>4}   (need >= {MIN_FLAGGED})")
    print(f"clean items     {len(clean):>4}   (need >= {MIN_CLEAN})")
    print(f"carriers        {len(carriers):>4}/{len(REQUIRED_CARRIERS)}")
    print(f"files covered   {len(files):>4}")
    print(f"records per carrier:")
    for carrier in sorted(carriers):
        n = sum(1 for i in flagged if i["carrier"] == carrier)
        print(f"    {carrier:20} {n:>3}")
    print("-" * 70)
    print(f"answer key      {hashlib.sha256(key_text.encode()).hexdigest()[:32]}")
    print("-" * 70)

    if errors:
        print(f"FAIL  {len(errors)} problem(s)")
        for err in errors[:25]:
            print(f"  - {err}")
        if len(errors) > 25:
            print(f"  ... and {len(errors) - 25} more")
        return 1

    print("PASS  every planted leak is where the key says it is")
    return 0


if __name__ == "__main__":
    sys.exit(main())
