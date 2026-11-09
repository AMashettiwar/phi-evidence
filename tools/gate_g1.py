#!/usr/bin/env python3
"""Gate G1: are the fixtures and the answer keys fit to score against?

The world (a site you can serve) and the corpus (1,680 standalone items) are
generated, keyed and frozen before any scanner runs on them. This gate checks
the freeze, the carrier matrix from the brief, the volume rules, that every
planted item has exactly one byte location, and that every do-not-flag
predicate has a clean fixture. Then it prints 20 items to read by eye.

Run:  python tools/gate_g1.py
"""

from __future__ import annotations

import hashlib
import json
import random
import sys
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORLD = ROOT / "fixtures" / "world"
CORPUS = ROOT / "fixtures" / "corpus"
KEYS = ROOT / "eval" / "keys"

# Brief 2.2, as one name per carrier the brief lists, plus data_file for the
# CSV / HL7 / X12 exports the brief's detection section names.
BRIEF_CARRIERS = {
    "visible_text", "html_comment", "css_hidden", "aria_hidden", "data_attribute",
    "json_ld", "url", "page_title", "response_header", "web_storage", "indexeddb",
    "cookie", "api_response", "third_party_request", "data_file", "pdf_text_layer",
    "document_metadata", "exif", "hidden_sheet", "tracked_changes", "speaker_notes",
    "error_surface", "log",
}
# The world's detector-facing carrier names, where one maps onto the brief's.
WORLD_TO_BRIEF = {
    "page_text": "visible_text", "title": "page_title", "url": "url",
    "css_hidden": "css_hidden", "print_css": "css_hidden", "html_attribute": "data_attribute",
    "aria_hidden": "aria_hidden", "json_ld": "json_ld", "browser_storage": "web_storage",
    "indexeddb": "indexeddb", "cookie": "cookie", "response_header": "response_header",
    "third_party": "third_party_request", "api_response": "api_response",
    "fhir_resource": "api_response", "downloadable_file": "data_file",
    "unlinked_file": "data_file", "file_metadata": "document_metadata",
    "dicom_header": "document_metadata", "error_surface": "error_surface", "log": "log",
    "hidden_sheet": "hidden_sheet", "tracked_changes": "tracked_changes",
    "speaker_notes": "speaker_notes", "exif": "exif",
}
MIN_PLANTED_WORLD = 40
MIN_NEGATIVE_SHARE = 0.40


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    problems: list[str] = []
    world_key_path, corpus_key_path = KEYS / "world_key.json", KEYS / "corpus_key.json"
    world = json.loads(world_key_path.read_text(encoding="utf-8"))["items"]
    corpus = json.loads(corpus_key_path.read_text(encoding="utf-8"))["items"]

    frozen_path = ROOT / "eval" / "frozen.json"
    frozen = json.loads(frozen_path.read_text(encoding="utf-8")) if frozen_path.exists() else {}
    for name, path in (("world", world_key_path), ("corpus", corpus_key_path)):
        if frozen.get(f"{name}_key_sha256") != sha256(path):
            problems.append(f"{name} key does not match eval/frozen.json")
    print(f"frozen               {'yes, ' + frozen.get('frozen_on', '') if frozen else 'NO'}")

    planted_world = [i for i in world if i["expected_flag"]]
    covered = ({WORLD_TO_BRIEF[i["carrier"]] for i in planted_world if i["carrier"] in WORLD_TO_BRIEF}
               | {i["carrier"] for i in corpus if i["expected_flag"]})
    missing = sorted(BRIEF_CARRIERS - covered)
    if missing:
        problems.append(f"brief carriers with no planted leak: {missing}")
    print(f"carrier matrix       {len(BRIEF_CARRIERS & covered)}/{len(BRIEF_CARRIERS)}")

    if len(planted_world) < MIN_PLANTED_WORLD:
        problems.append(f"world has {len(planted_world)} planted leaks, need {MIN_PLANTED_WORLD}")
    negatives = sum(1 for i in corpus if not i["expected_flag"])
    share = negatives / len(corpus)
    if share < MIN_NEGATIVE_SHARE:
        problems.append(f"corpus negatives are {share:.1%}, need {MIN_NEGATIVE_SHARE:.0%}")
    strata = Counter(i["stratum"] for i in corpus if i["expected_flag"])
    print(f"world planted        {len(planted_world)}")
    print(f"corpus               {len(corpus)} items, {negatives} negative ({share:.1%}), "
          f"positives per stratum {min(strata.values())}-{max(strata.values())}")

    ambiguous = []
    for item in world:
        data = (WORLD / item["file"]).read_bytes()
        needle = item["value"].encode("utf-8")
        if data.count(needle) != 1 or data.find(needle) != item["offset"]:
            ambiguous.append(item["id"])
    for item in corpus:
        data = (CORPUS / item["file"]).read_bytes()
        raw = item["raw"].encode("utf-8")
        if data.count(raw) != 1 or data[item["offset"]:item["offset"] + item["length"]] != raw:
            ambiguous.append(item["id"])
    if ambiguous:
        problems.append(f"{len(ambiguous)} items without exactly one byte location: {ambiguous[:5]}")
    print(f"one location each    {len(world) + len(corpus) - len(ambiguous)}/{len(world) + len(corpus)}")

    predicates = yaml.safe_load((ROOT / "policy" / "negatives.yaml").read_text(encoding="utf-8"))
    clean_files = {i["file"] for i in world if not i["expected_flag"]}
    unbacked = [f for p in predicates["predicates"] for f in p["fixtures"] if f not in clean_files]
    if unbacked:
        problems.append(f"negative fixtures not keyed as clean: {unbacked}")
    print(f"negative fixtures    {8 - len(unbacked)}/8 keyed clean in the world")

    print("\nSAMPLE (20 items, fixed seed)")
    for item in random.Random(1).sample(world + corpus, 20):
        where = item["file"] + ("" if "raw" not in item else f" ({item['stratum']})")
        flag = "flag " if item["expected_flag"] else "clean"
        print(f"  {flag} {item['carrier']:20} @{item['offset']:<6} {item['value'][:34]:34} {where}")

    if problems:
        print(f"\nFAIL  {len(problems)} problem(s)")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("\nPASS  fixtures and keys frozen and fit to score")
    return 0


if __name__ == "__main__":
    sys.exit(main())
