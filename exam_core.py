"""Pure helpers for the exam runner. No Streamlit import, so they can be tested."""

from __future__ import annotations

import zipfile
from collections import Counter, defaultdict
from pathlib import Path

from phi_scan.detect import digest


def extract(archive: zipfile.ZipFile, target: Path) -> int:
    """Extract a zip safely. Returns how many files were written."""
    written = 0
    root = target.resolve()
    for member in archive.infolist():
        name = member.filename
        if name.startswith("__MACOSX") or name.endswith("/"):
            continue
        path = (target / name).resolve()
        if not str(path).startswith(str(root)):
            continue  # zip-slip
        path.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(member) as source, open(path, "wb") as sink:
            sink.write(source.read())
        written += 1
    return written


def forms(item: dict) -> set[str]:
    """Every string a finding could legitimately be hashed as."""
    out: set[str] = set()

    def add(text: str) -> None:
        text = " ".join(text.split())
        if text:
            out.update({text, text.upper(), text.lower(), text.title()})

    for value in [item.get("value") or "", *(item.get("alt") or [])]:
        value = value.strip()
        if not value:
            continue
        add(value)
        if "^" in value:
            parts = [p for p in value.split("^") if p]
            if len(parts) >= 2:
                last, first = parts[0], parts[1]
                for combo in (f"{first} {last}", f"{last} {first}", f"{last}, {first}"):
                    add(combo)
        if value.count(",") == 1:
            last, first = [p.strip() for p in value.split(",")]
            if last and first:
                add(f"{first} {last}")
                add(f"{last} {first}")
    return out


def score(key: dict, findings: list[dict]) -> dict:
    reported: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        doc = finding["path"].split("/")[-1].split(".")[0]
        reported[doc] |= set(finding["value_hashes"])

    rows: list[dict] = []
    matched = missed = traps = excluded = 0
    by_cat: Counter[str] = Counter()

    for item in key.get("items", []):
        doc = item.get("doc", "")
        hashes = reported.get(doc, set())
        hit = any(digest(f) in hashes for f in forms(item))
        kind = item.get("kind")
        if kind == "phi":
            if hit:
                matched += 1
            else:
                missed += 1
                by_cat[item.get("cat", "?")] += 1
            rows.append({
                "doc": doc,
                "category": item.get("cat"),
                "tier": item.get("tier"),
                "kind": kind,
                "found": hit,
            })
        elif kind == "trap" and hit:
            traps += 1
        elif kind == "excluded" and hit:
            excluded += 1

    total = matched + missed
    return {
        "matched": matched,
        "missed": missed,
        "total": total,
        "recall": matched / total if total else 0.0,
        "traps": traps,
        "excluded": excluded,
        "precision": matched / (matched + traps + excluded) if matched else 0.0,
        "by_cat": by_cat,
        "rows": rows,
    }
