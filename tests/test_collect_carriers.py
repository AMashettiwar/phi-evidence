"""One test per collector carrier: a planted marker must surface under its label."""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "fixtures"))

import docgen  # noqa: E402
from phi_scan.collect import collect  # noqa: E402
from phi_scan.vault import Vault  # noqa: E402

MARK = "Zelda Marker-7731"


def spans(tmp_path, monkeypatch, files: dict[str, bytes | str]) -> dict[str, list[str]]:
    """Collect files into tmp_path and return carrier -> span texts."""
    monkeypatch.setenv("PHI_EVIDENCE_KEYS", str(tmp_path / "keys"))
    source = tmp_path / "src"
    for name, content in files.items():
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    out = tmp_path / "out"
    collect(source, out)
    vault = Vault(out / "vault")
    found: dict[str, list[str]] = {}
    for line in (out / "index.jsonl").read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        raw = vault.get(row["doc"])[row["offset"]:row["offset"] + row["length"]]
        found.setdefault(row["carrier"], []).append(raw.decode("utf-8", "replace"))
    return found


def has(found, carrier, needle=MARK):
    return any(needle in text for text in found.get(carrier, []))


def test_aria_hidden(tmp_path, monkeypatch):
    html = f'<html><body><span aria-hidden="true">{MARK} dx</span></body></html>'
    assert has(spans(tmp_path, monkeypatch, {"a.html": html}), "aria_hidden")


def test_json_ld(tmp_path, monkeypatch):
    html = ('<html><script type="application/ld+json">'
            f'{{"@type": "Patient", "name": "{MARK}"}}</script></html>')
    assert has(spans(tmp_path, monkeypatch, {"a.html": html}), "json_ld")


def test_indexeddb(tmp_path, monkeypatch):
    html = ('<script>const r = indexedDB.open("v");\n'
            f'r.objectStore("v").put({{name: "{MARK}", dx: "x"}});</script>')
    found = spans(tmp_path, monkeypatch, {"a.html": html})
    assert has(found, "indexeddb")
    assert not has(found, "indexeddb", "indexedDB.open")


def test_cookie(tmp_path, monkeypatch):
    html = f'<script>document.cookie = "c=" + encodeURIComponent("{MARK}") + "; path=/";</script>'
    assert has(spans(tmp_path, monkeypatch, {"a.html": html}), "cookie")


def test_response_header(tmp_path, monkeypatch):
    headers = f"/portal\n  Set-Cookie: who={MARK}\n  X-Other: 1\n"
    redirects = f"/old  /new?who={MARK}  302\n"
    found = spans(tmp_path, monkeypatch, {"site/_headers": headers, "site/_redirects": redirects})
    assert len([t for t in found["response_header"] if MARK in t]) == 2
    assert not any(t.startswith("/portal") for t in found["response_header"])


def test_hidden_sheet(tmp_path, monkeypatch):
    book = docgen.build_xlsx([
        {"name": "Shown", "rows": [["visible", "row"]]},
        {"name": "Secret", "hidden": True, "rows": [[MARK, "F33.1"], ["other", "row"]]}])
    found = spans(tmp_path, monkeypatch, {"b.xlsx": book})
    assert has(found, "hidden_sheet")
    assert not has(found, "hidden_sheet", "visible")


def test_tracked_changes(tmp_path, monkeypatch):
    doc = docgen.build_docx(["body"], deleted=[f"{MARK} removed"], inserted=["added text"])
    found = spans(tmp_path, monkeypatch, {"d.docx": doc})
    assert has(found, "tracked_changes")
    assert has(found, "tracked_changes", "added text")


def test_file_metadata_core_properties(tmp_path, monkeypatch):
    doc = docgen.build_docx(["body"], core={"creator": MARK, "title": "T"})
    found = spans(tmp_path, monkeypatch, {"d.docx": doc})
    assert has(found, "file_metadata", f"creator: {MARK}")
    assert has(found, "file_metadata", "title: T")


def test_speaker_notes(tmp_path, monkeypatch):
    deck = docgen.build_pptx([{"text": "slide", "notes": f"{MARK} notes"}])
    assert has(spans(tmp_path, monkeypatch, {"p.pptx": deck}), "speaker_notes")


def test_exif(tmp_path, monkeypatch):
    jpeg = docgen.build_jpeg({"Artist": MARK, "Software": "cam 1.0"})
    found = spans(tmp_path, monkeypatch, {"i.jpg": jpeg})
    assert has(found, "exif", f"Artist: {MARK}")
    assert has(found, "exif", "Software: cam 1.0")


def test_bad_inputs_do_not_stop_the_scan(tmp_path, monkeypatch):
    found = spans(tmp_path, monkeypatch, {
        "bad.xlsx": b"not a zip", "bad.jpg": b"\xff\xd8\xff\xe1\x00\x10Exif\x00\x00II",
        "ok.html": f'<span aria-hidden="true">{MARK}</span>'})
    assert has(found, "aria_hidden")
