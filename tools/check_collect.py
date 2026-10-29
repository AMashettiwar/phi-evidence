#!/usr/bin/env python3
"""Gate G2b: can the collector see every planted leak, without storing any of it?

The check is deliberately harsh. A planted leak only counts as collected if some
observation carries the *right carrier label* and its span really contains the
value. Merely having the file in the vault does not count.

Run:  python tools/check_collect.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "pylibs"))

from phi_scan.collect import collect  # noqa: E402
from phi_scan.vault import Vault  # noqa: E402

WORLD = ROOT / "fixtures" / "world"
ARTIFACTS = ROOT / "artifacts"
RUNS = 3
SAMPLE = 20


def load_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def main() -> int:
    key = json.loads((ROOT / "eval" / "keys" / "world_key.json").read_text(encoding="utf-8"))
    items = key["items"]
    planted = [item for item in items if item["expected_flag"]]
    failures: list[str] = []

    # --- run three times ---------------------------------------------------
    manifests = []
    for run in range(RUNS):
        manifests.append(collect(WORLD, ARTIFACTS / f"run{run}", str(ROOT / "pylibs")))
    hashes = {m["index_sha256"] for m in manifests}
    print(f"runs                {RUNS}")
    print(f"distinct index hash {len(hashes)}")
    if len(hashes) != 1:
        failures.append(f"collection is not deterministic: {len(hashes)} distinct hashes")

    manifest = manifests[0]
    rows = load_rows(ARTIFACTS / "run0" / "index.jsonl")
    vault = Vault(ARTIFACTS / "run0" / "vault")
    by_path: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_path[row["path"]].append(row)

    def doc_bytes(digest: str) -> bytes:
        if digest not in cache:
            cache[digest] = vault.get(digest)
        return cache[digest]

    cache: dict[str, bytes] = {}

    # --- extraction recall, carrier must match -----------------------------
    any_miss: list[str] = []
    carrier_miss: list[str] = []
    carrier_total: dict[str, int] = defaultdict(int)
    carrier_hit: dict[str, int] = defaultdict(int)

    for item in planted:
        value = item["value"].encode("utf-8")
        carrier = item["carrier"]
        carrier_total[carrier] += 1
        found_somewhere = False
        found_with_carrier = False
        for row in by_path.get(item["file"], []):
            span = doc_bytes(row["doc"])[row["offset"]:row["offset"] + row["length"]]
            if value in span:
                found_somewhere = True
                if row["carrier"] == carrier:
                    found_with_carrier = True
                    break
        if not found_somewhere:
            any_miss.append(f"{item['id']} {item['file']} [{carrier}]")
        elif not found_with_carrier:
            carrier_miss.append(f"{item['id']} {item['file']} [{carrier}]")
        else:
            carrier_hit[carrier] += 1

    print(f"observations        {manifest['observations']}")
    print(f"planted leaks       {len(planted)}")
    print(f"bytes seen          {len(planted) - len(any_miss)}/{len(planted)}")
    print(f"label correct       {len(planted) - len(carrier_miss) - len(any_miss)}/{len(planted)}")
    if any_miss:
        failures.append(f"{len(any_miss)} planted values were never extracted")
    if carrier_miss:
        failures.append(f"{len(carrier_miss)} values were extracted under the wrong label")

    # --- carrier coverage --------------------------------------------------
    key_carriers = {item["carrier"] for item in planted}
    seen = set(manifest["carriers"])
    missing = key_carriers - seen
    print(f"carriers            {len(key_carriers & seen)}/{len(key_carriers)}")
    if missing:
        failures.append(f"carriers never produced: {sorted(missing)}")

    # --- the index must contain no patient value ---------------------------
    blob = (ARTIFACTS / "run0" / "index.jsonl").read_text(encoding="utf-8")
    blob += (ARTIFACTS / "run0" / "manifest.json").read_text(encoding="utf-8")
    leaked = [item["id"] for item in planted if item["value"] in blob]
    print(f"values in index     {len(leaked)}  (must be 0)")
    if leaked:
        failures.append(f"index contains patient values: {leaked[:5]}")

    # --- replay a sample ---------------------------------------------------
    sample = rows[:SAMPLE]
    replayed = 0
    for row in sample:
        payload = doc_bytes(row["doc"])
        span = payload[row["offset"]:row["offset"] + row["length"]]
        if not span:
            failures.append(f"{row['obs_id']}: empty span")
            continue
        if row["derivation"] == "raw":
            if payload != (WORLD / row["path"]).read_bytes():
                failures.append(f"{row['obs_id']}: vault copy does not match the source file")
                continue
        replayed += 1
    print(f"replayed            {replayed}/{SAMPLE}")
    if replayed != SAMPLE:
        failures.append("replay failed for part of the sample")

    # --- report ------------------------------------------------------------
    print()
    print(f"{'carrier':22} {'found':>6} {'of':>4}")
    for carrier in sorted(carrier_total):
        print(f"{carrier:22} {carrier_hit[carrier]:>6} {carrier_total[carrier]:>4}")
    print()

    if carrier_miss:
        print("wrong label:")
        for line in carrier_miss[:10]:
            print(f"  - {line}")
    if any_miss:
        print("never extracted:")
        for line in any_miss[:10]:
            print(f"  - {line}")

    if failures:
        print(f"FAIL  {len(failures)} problem(s)")
        for item in failures:
            print(f"  - {item}")
        return 1

    print("PASS  every planted leak is collectable, labelled, and the index holds no PHI")
    return 0


if __name__ == "__main__":
    sys.exit(main())
