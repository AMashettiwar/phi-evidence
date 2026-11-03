#!/usr/bin/env python3
"""Gate G3: does the detector find the leaks, and only the leaks?

Scoring is against the frozen answer key. A planted leak counts as caught only
if a finding exists on the same file and carrier whose evidence span actually
contains the planted value. A finding that matches no planted leak is a false
alarm.

Run:  python tools/check_detect.py
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "pylibs"))

from phi_scan.collect import collect  # noqa: E402
from phi_scan.detect import detect  # noqa: E402
from phi_scan.vault import Vault  # noqa: E402

WORLD = ROOT / "fixtures" / "world"
OUT = ROOT / "artifacts" / "g3"
NEVER_MISS = {"ssn", "mrn", "plan_id"}
# Paths the operator declares as behind a login. Static collection cannot tell.
AUTH_PREFIXES = ("portal", "api/v2/patients")
# The scan runs as the scope's account; its own record is not a finding.
SCOPE = yaml.safe_load((ROOT / "fixtures" / "scope.yaml").read_text(encoding="utf-8"))
OWN_IDS = frozenset(a["patient_id"] for a in SCOPE["accounts"] if a["name"] == SCOPE["scan_as"])


def main() -> int:
    manifest = collect(WORLD, OUT, str(ROOT / "pylibs"))
    findings = detect(OUT / "index.jsonl", OUT / "vault", AUTH_PREFIXES, context="public-web",
                      own_ids=OWN_IDS)
    vault = Vault(OUT / "vault")
    cache: dict[str, bytes] = {}

    def finding_span(finding: dict) -> bytes:
        """The exact bytes a finding points at, not the whole observation."""
        key = finding["doc"]
        if key not in cache:
            cache[key] = vault.get(key)
        return cache[key][finding["offset"]:finding["offset"] + finding["length"]]

    def digest(value: str) -> str:
        return vault.token(value)

    # Every finding must point at real bytes. A pointer that resolves to nothing
    # is not evidence.
    for finding in findings:
        if not finding_span(finding):
            print(f"EMPTY EVIDENCE {finding['finding_id']} {finding['path']}")
            return 1

    key = json.loads((ROOT / "eval" / "keys" / "world_key.json").read_text(encoding="utf-8"))
    planted = [item for item in key["items"] if item["expected_flag"]]
    clean = [item for item in key["items"] if not item["expected_flag"]]

    by_spot: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for finding in findings:
        by_spot[(finding["path"], finding["carrier"])].append(finding)

    # --- recall ------------------------------------------------------------
    missed: list[tuple[dict, str]] = []
    caught: list[dict] = []
    per_carrier_hit: dict[str, int] = defaultdict(int)
    per_carrier_total: dict[str, int] = defaultdict(int)
    used_findings: set[str] = set()
    match_count: dict[str, int] = defaultdict(int)
    hit_for: dict[str, dict] = {}

    for item in planted:
        per_carrier_total[item["carrier"]] += 1
        candidates = by_spot.get((item["file"], item["carrier"]), [])
        wanted = digest(item["value"])
        hit = next((f for f in candidates if wanted in f["value_hashes"]), None)
        if hit is None:
            reason = ("no finding on this file and carrier" if not candidates
                      else "finding emitted, but not on this record")
            missed.append((item, reason))
        else:
            caught.append(item)
            used_findings.add(hit["finding_id"])
            match_count[hit["finding_id"]] += 1
            hit_for[item["id"]] = hit
            per_carrier_hit[item["carrier"]] += 1

    # --- false alarms ------------------------------------------------------
    false_alarms: list[dict] = []
    for finding in findings:
        if finding["finding_id"] in used_findings:
            continue
        # Could it be a second valid leak in the same record? Check every planted
        # value on that spot before calling it wrong.
        needle_ok = False
        for item in planted:
            if item["file"] == finding["path"] and item["carrier"] == finding["carrier"]:
                if digest(item["value"]) in finding["value_hashes"]:
                    needle_ok = True
                    break
        if not needle_ok:
            false_alarms.append(finding)

    recall = len(caught) / len(planted) if planted else 0.0
    precision = len(used_findings) / len(findings) if findings else 0.0

    print("=" * 70)
    print("DETECTION GATE")
    print("=" * 70)
    print(f"observations        {manifest['observations']}")
    print(f"findings emitted    {len(findings)}")
    print(f"planted leaks       {len(planted)}")
    print(f"caught              {len(caught)}")
    print(f"missed              {len(missed)}")
    print(f"false alarms        {len(false_alarms)}")
    print(f"recall              {recall:6.1%}")
    print(f"precision           {precision:6.1%}")
    print()

    print(f"{'carrier':22} {'caught':>6} {'of':>4}")
    for carrier in sorted(per_carrier_total):
        flag = "" if per_carrier_hit[carrier] == per_carrier_total[carrier] else "  <-- gap"
        print(f"{carrier:22} {per_carrier_hit[carrier]:>6} {per_carrier_total[carrier]:>4}{flag}")
    print()

    never = [item for item in planted if NEVER_MISS & set(item["identifiers"])]
    never_caught = [item for item in never if item in caught]
    print(f"always-flag records {len(never_caught)}/{len(never)}")
    print()

    level_bad = [(item, hit_for[item["id"]]["level"]) for item in planted
                 if item["id"] in hit_for
                 and hit_for[item["id"]]["level"] != item["expected_level"]]
    print(f"level agreement     {len(planted) - len(level_bad)}/{len(planted)}")
    if level_bad:
        print("LEVEL DISAGREEMENTS (key, then code)")
        for item, got in level_bad:
            print(f"  - {item['id']:5} {item['file']:32} [{item['carrier']:15}] "
                  f"key={item['expected_level']:9} code={got}")
    print()

    if missed:
        print("MISSES")
        for item, reason in missed[:15]:
            print(f"  - {item['id']:5} {item['file']:38} [{item['carrier']:18}] {reason}")
        print()
    if false_alarms:
        print("FALSE ALARMS")
        for finding in false_alarms[:15]:
            print(f"  - {finding['path']:38} [{finding['carrier']:18}] "
                  f"{finding['value_mask']:14} {finding['identifiers']}")
        print()

    extras = [f for f in findings
              if f["finding_id"] not in used_findings and f not in false_alarms]
    if extras:
        print("EXTRA FINDINGS (another view of an already-caught leak)")
        for finding in extras[:12]:
            print(f"  - {finding['path']:38} [{finding['carrier']:16}] "
                  f"{finding['extraction']:20} {finding['value_mask']}")
        print()

    doubles = {k: v for k, v in match_count.items() if v > 1}
    print(f"findings covering >1 leak  {len(doubles)}")
    if doubles:
        for finding_id, count in sorted(doubles.items()):
            detail = next(f for f in findings if f["finding_id"] == finding_id)
            print(f"  - {finding_id} {detail['path']} [{detail['carrier']}] covers {count}")

    # --- the output must not contain a patient value -----------------------
    rendered = json.dumps(findings, sort_keys=True)
    leaked = [item["id"] for item in planted if item["value"] in rendered]
    print(f"values in findings         {len(leaked)}  (must be 0)")
    if leaked:
        print(f"  patient values present: {leaked[:5]}")

    # --- same input, same findings -----------------------------------------
    again = detect(OUT / "index.jsonl", OUT / "vault", AUTH_PREFIXES, context="public-web",
                      own_ids=OWN_IDS)
    stable = json.dumps(again, sort_keys=True) == rendered
    print(f"detection deterministic    {stable}")

    # --- invariant 3: no rule id outside the closed registry ----------------
    rules = yaml.safe_load((ROOT / "policy" / "rules.yaml").read_text(encoding="utf-8"))
    registry = {rule["id"] for rule in rules["rules"]}
    unknown = sorted({rule for finding in findings for rule in finding["rules"]} - registry)
    print(f"rule ids outside registry  {len(unknown)}  (must be 0)")

    failures: list[str] = []
    if unknown:
        failures.append(f"rule ids outside the registry: {unknown}")
    if missed:
        failures.append(f"{len(missed)} planted leaks missed")
    if leaked:
        failures.append("findings output contains patient values")
    if not stable:
        failures.append("detection is not deterministic")
    if doubles:
        failures.append(f"{len(doubles)} findings each cover more than one leak")
    if missed:
        failures.append(f"{len(missed)} planted leaks missed")
    if len(never_caught) != len(never):
        failures.append("a never-miss identifier was missed")
    if false_alarms:
        failures.append(f"{len(false_alarms)} false alarms")

    if failures:
        print(f"FAIL  {len(failures)} problem(s)")
        for item in failures:
            print(f"  - {item}")
        return 1

    print("PASS  every planted leak caught, no false alarms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
