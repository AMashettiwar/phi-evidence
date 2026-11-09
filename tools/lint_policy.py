#!/usr/bin/env python3
"""Check the policy files are complete, consistent, and honestly sourced.

Prints a short table, then PASS or FAIL. Exit code 0 means pass.
No network. No AI. Same input always gives the same output.

The quote check is the important one: every rule quote must appear in the
regulation text that tools/fetch_sources.py downloaded. If the source text is
missing, this fails and tells you to run the fetch script.
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ID_PATH = ROOT / "policy" / "identifiers.yaml"
RULE_PATH = ROOT / "policy" / "rules.yaml"
SEV_PATH = ROOT / "policy" / "severity.yaml"
SRC_DIR = ROOT / "policy" / "source"

LETTERS = set("ABCDEFGHIJKLMNOPQR")
ID_FIELDS = [
    "key", "letter", "label", "citation", "how_we_find", "must_pass_check",
    "mask", "mask_example", "always_flag", "severity",
]
RULE_FIELDS = [
    "id", "title", "citation", "plain_meaning", "url", "contested",
    "quote", "quote_status", "source_key",
]
MUST_ALWAYS_FLAG = {"ssn", "mrn", "plan_id"}
CITATION_RE = re.compile(r"^164\.514\(b\)\(2\)\(i\)\(([A-R])\)$")
LEVELS = {"critical", "high", "medium", "review"}

errors: list[str] = []


def sha16(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def main() -> int:
    for path in (ID_PATH, RULE_PATH, SEV_PATH):
        if not path.exists():
            print(f"FAIL missing file: {path}")
            return 1

    id_doc = yaml.safe_load(ID_PATH.read_text(encoding="utf-8"))
    rule_doc = yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))
    sev_doc = yaml.safe_load(SEV_PATH.read_text(encoding="utf-8"))

    rows = id_doc.get("identifiers") or []
    rules = rule_doc.get("rules") or []
    id_keys = {r.get("key") for r in rows}

    # --- identifiers -------------------------------------------------------
    if len(rows) != 18:
        errors.append(f"identifier count is {len(rows)}, expected 18")

    keys = [r.get("key") for r in rows]
    if len(set(keys)) != len(keys):
        errors.append("duplicate identifier keys")

    letters: list[str] = []
    for row in rows:
        tag = row.get("key", "<missing key>")
        for field in ID_FIELDS:
            if field not in row:
                errors.append(f"{tag}: missing field '{field}'")
            elif row[field] in (None, ""):
                errors.append(f"{tag}: empty field '{field}'")

        citation = str(row.get("citation", ""))
        match = CITATION_RE.match(citation)
        if not match:
            errors.append(f"{tag}: citation '{citation}' is not in the 164.514(b)(2)(i)(X) shape")
        else:
            letters.append(match.group(1))
            if match.group(1) != str(row.get("letter", "")):
                errors.append(f"{tag}: letter field disagrees with citation")

    missing = LETTERS - set(letters)
    extra = set(letters) - LETTERS
    if missing:
        errors.append(f"letters missing from table: {sorted(missing)}")
    if extra:
        errors.append(f"letters not in A-R: {sorted(extra)}")
    if len(letters) != len(set(letters)):
        errors.append("a letter is used more than once")

    always = {r.get("key") for r in rows if r.get("always_flag") is True}
    if always != MUST_ALWAYS_FLAG:
        errors.append(f"always-flag set is {sorted(always)}, must be {sorted(MUST_ALWAYS_FLAG)}")

    # --- severity ----------------------------------------------------------
    levels = sev_doc.get("meta", {}).get("levels") or []
    if set(levels) != LEVELS:
        errors.append(f"severity levels are {levels}, expected {sorted(LEVELS)}")

    standalone = sev_doc.get("standalone") or {}
    unknown = set(standalone) - id_keys
    if unknown:
        errors.append(f"severity names unknown identifiers: {sorted(unknown)}")
    for key, level in standalone.items():
        if level not in LEVELS:
            errors.append(f"severity for {key} is '{level}', not a known level")

    critical = {k for k, v in standalone.items() if v == "critical"}
    if critical != MUST_ALWAYS_FLAG:
        errors.append(f"critical standalone set is {sorted(critical)}, must be {sorted(MUST_ALWAYS_FLAG)}")
    if standalone.get("geography") != "medium":
        errors.append("geography must be standalone medium (strict address rule)")

    heightened = sev_doc.get("heightened") or []
    heightened_keys = [h.get("key") for h in heightened]
    if len(set(heightened_keys)) != len(heightened_keys):
        errors.append("duplicate heightened categories")
    rule_ids = {r.get("id") for r in rules}
    for entry in heightened:
        if entry.get("rule") not in rule_ids:
            errors.append(f"heightened {entry.get('key')}: rule '{entry.get('rule')}' is not a rule id")

    # --- rules -------------------------------------------------------------
    if len(rules) != rule_doc.get("meta", {}).get("count"):
        errors.append("rule count disagrees with meta.count")
    if len(rules) != 12:
        errors.append(f"rule count is {len(rules)}, expected 12")

    if len({r.get("id") for r in rules}) != len(rules):
        errors.append("duplicate rule ids")

    verified = 0
    not_required = 0
    pending = 0
    for rule in rules:
        tag = rule.get("id", "<missing id>")
        for field in RULE_FIELDS:
            if field not in rule:
                errors.append(f"{tag}: missing field '{field}'")
        url = str(rule.get("url", ""))
        if not url.startswith("https://"):
            errors.append(f"{tag}: url must start with https://")
        if rule.get("contested") is True and not rule.get("contested_note"):
            errors.append(f"{tag}: contested rule needs a contested_note")

        status = rule.get("quote_status")
        quote = rule.get("quote")
        if status not in ("verified", "not_required", "pending"):
            errors.append(f"{tag}: unknown quote_status '{status}'")

        if status == "verified":
            verified += 1
            if not quote:
                errors.append(f"{tag}: verified but has no quote")
                continue
            source_key = rule.get("source_key")
            if not source_key:
                errors.append(f"{tag}: verified quote needs a source_key")
                continue
            source_file = SRC_DIR / f"{source_key}.txt"
            if not source_file.exists():
                errors.append(f"{tag}: source {source_key}.txt missing - run tools/fetch_sources.py")
                continue
            body = norm(source_file.read_text(encoding="utf-8"))
            if norm(quote) not in body:
                errors.append(f"{tag}: quote does not appear in the stored source text")
        elif status == "not_required":
            not_required += 1
            if quote:
                errors.append(f"{tag}: not_required but has a quote")
            if not rule.get("why_no_quote"):
                errors.append(f"{tag}: not_required needs why_no_quote")
        else:
            pending += 1
            if quote:
                errors.append(f"{tag}: has a quote but status is pending")

    # --- report ------------------------------------------------------------
    print("=" * 70)
    print("POLICY CHECK")
    print("=" * 70)
    print(f"identifiers        {len(rows):>3}/18    letters A-R present: {not missing and not extra}")
    print(f"always-flag        {len(always):>3}/3     {', '.join(sorted(always))}")
    print(f"rules              {len(rules):>3}/12    ids unique: {len({r.get('id') for r in rules}) == len(rules)}")
    print(f"severity levels    {len(levels):>3}/4     standalone rules: {len(standalone)}")
    print(f"heightened tags    {len(heightened):>3}       {', '.join(heightened_keys)}")
    print(f"quotes verified    {verified:>3}/12    not required: {not_required}   pending: {pending}")
    print(f"source text files  {len(list(SRC_DIR.glob('*.txt'))) if SRC_DIR.exists() else 0:>3}       in policy/source")
    print("-" * 70)
    for path in (ID_PATH, RULE_PATH, SEV_PATH):
        print(f"{path.name:22} sha256 {sha16(path)}")
    print("-" * 70)

    if errors:
        print(f"FAIL  {len(errors)} problem(s)")
        for err in errors:
            print(f"  - {err}")
        return 1

    print("PASS  policy files are complete, consistent, and quoted from source")
    return 0


if __name__ == "__main__":
    sys.exit(main())
