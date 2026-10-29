#!/usr/bin/env python3
"""Download the exact regulation text from eCFR and save it locally.

We do not quote a regulation from memory. This script pulls the official text,
normalises whitespace, stores one paragraph per line, and records a hash of
every file so later checks can prove the quotes came from this text.

eCFR's XML endpoint refuses requests that do not accept compression, so the
request asks for gzip and unpacks it here.

Run:  python tools/fetch_sources.py
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "policy" / "source"
BASE = "https://www.ecfr.gov/api/versioner/v1"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) phi-scan-prototype/0.1"

# key, title, part, section, phrase to show me when printing excerpts
SECTIONS = [
    ("phi_definition", 45, 160, "160.103", "Individually identifiable health information means"),
    ("expert_determination", 45, 164, "164.514", "A covered entity may determine that health information is not"),
    ("safe_harbor", 45, 164, "164.514", "The following identifiers of the individual"),
    ("actual_knowledge", 45, 164, "164.514", "actual knowledge"),
    ("permitted_disclosure", 45, 164, "164.502", "A covered entity or business associate may not use or disclose"),
    ("reproductive_health", 45, 164, "164.502", "reproductive health care"),
    ("transmission_security", 45, 164, "164.312", "Guard against unauthorized access to electronic protected health information"),
    ("access_control_audit", 45, 164, "164.312", "Implement technical policies and procedures for electronic information systems"),
    ("activity_review", 45, 164, "164.308", "Review records of information system activity"),
    ("accounting_of_disclosures", 45, 164, "164.528", "accounting of disclosures"),
    ("part2_sud", 42, 2, "2.12", "records of the identity, diagnosis, prognosis, or treatment"),
]


def localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def fetch(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": UA, "Accept-Encoding": "gzip, deflate"},
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        body = response.read()
        encoding = (response.headers.get("Content-Encoding") or "").lower()
    if encoding == "gzip":
        body = gzip.decompress(body)
    elif encoding == "deflate":
        try:
            body = zlib.decompress(body)
        except zlib.error:
            body = zlib.decompress(body, -zlib.MAX_WBITS)
    return body


def latest_date(title: int) -> str:
    data = json.loads(fetch(f"{BASE}/titles.json"))
    for entry in data.get("titles", []):
        if int(entry.get("number", -1)) == title:
            for field in ("latest_issue_date", "up_to_date_as_of", "latest_amended_on"):
                if entry.get(field):
                    return entry[field]
    raise SystemExit(f"could not find a date for title {title}")


def paragraphs(xml_bytes: bytes) -> list[str]:
    root = ET.fromstring(xml_bytes)
    found: list[str] = []
    for element in root.iter():
        if localname(element.tag) in ("P", "FP"):
            text = "".join(element.itertext())
            text = re.sub(r"\s+", " ", text).strip()
            if text:
                found.append(text)
    return found


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    dates: dict[int, str] = {}
    index: list[dict] = []
    failures: list[str] = []

    for key, title, part, section, probe in SECTIONS:
        if title not in dates:
            dates[title] = latest_date(title)
            print(f"title {title}: current as of {dates[title]}")

        url = f"{BASE}/full/{dates[title]}/title-{title}.xml?part={part}&section={section}"
        try:
            raw = fetch(url)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{key}: download failed ({type(exc).__name__}: {exc})")
            print(f"  {key:26} DOWNLOAD FAILED {exc}")
            continue

        try:
            paras = paragraphs(raw)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{key}: parse failed ({exc})")
            print(f"  {key:26} PARSE FAILED {exc}")
            continue

        if not paras:
            failures.append(f"{key}: no paragraphs returned")
            print(f"  {key:26} EMPTY")
            continue

        text = "\n".join(paras) + "\n"
        path = OUT / f"{key}.txt"
        path.write_bytes(text.encode("utf-8"))
        index.append({
            "key": key,
            "title": title,
            "part": part,
            "section": section,
            "url": url,
            "as_of": dates[title],
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size,
            "paragraphs": len(paras),
            "probe_found": probe.lower() in text.lower(),
        })
        print(f"  {key:26} {len(paras):4} paragraphs  {path.stat().st_size:7} bytes  probe={probe.lower() in text.lower()}")
        time.sleep(1.0)

    (OUT / "index.json").write_text(
        json.dumps({"sections": index, "failures": failures}, indent=2) + "\n",
        encoding="utf-8",
    )

    print("-" * 72)
    print(f"saved {len(index)}/{len(SECTIONS)} sections, {len(failures)} failures")
    for failure in failures:
        print(f"  - {failure}")

    if failures:
        return 1

    print("\n=== excerpts around the phrases we need to quote ===")
    for entry in index:
        text = (OUT / f"{entry['key']}.txt").read_text(encoding="utf-8")
        wanted = next(p for k, _, _, _, p in SECTIONS if k == entry["key"])
        lines = text.splitlines()
        hits = [i for i, line in enumerate(lines) if wanted.lower() in line.lower()]
        print(f"\n--- {entry['key']} ({entry['section']}) ---")
        if not hits:
            print("  no line matched the probe phrase")
            continue
        first = hits[0]
        for i in range(first, min(first + 2, len(lines))):
            print(f"  [{i}] {lines[i][:600]}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
