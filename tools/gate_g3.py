#!/usr/bin/env python3
"""Gate G3 (metamorphic part): the same finding, in every carrier.

One record, a person and a diagnosis, is planted in each carrier the brief
lists. Moving a finding from one place to another must not lose it: a detector
that finds a name in a paragraph but not in a hidden spreadsheet, a tracked
change or an EXIF caption has learned the fixture, not the problem. Then the
hard negatives the brief names must stay clean.

The planted-world recall half of G3 is tools/check_detect.py.

Run:  python tools/gate_g3.py
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "fixtures"))

from docgen import build_docx, build_jpeg, build_pdf, build_pptx, build_xlsx  # noqa: E402
from phi_scan.collect import collect  # noqa: E402
from phi_scan.detect import detect  # noqa: E402
from phi_scan.vault import Vault  # noqa: E402

OUT = ROOT / "artifacts" / "g3_invariance"
NAME, DX, MRN = "Imogen Castellano", "relapsing-remitting multiple sclerosis", "MRN-447201"
LINE = f"{NAME} - {DX}"


def page(body: str, head: str = "") -> str:
    return f"<!doctype html><html><head><title>Clinic</title>{head}</head><body>{body}</body></html>"


CARRIERS: dict[str, tuple[str, str | bytes]] = {
    "visible_text": ("visible.html", page(f"<p>{LINE}</p>")),
    "html_comment": ("comment.html", page(f"<p>Welcome.</p><!-- {LINE} -->")),
    "css_hidden": ("hidden.html", page(f'<div style="display:none">{LINE}</div>')),
    "aria_hidden": ("aria.html", page(f'<span aria-hidden="true">{LINE}</span>')),
    "data_attribute": ("data.html", page(f'<div data-patient="{LINE}">Hi</div>')),
    "json_ld": ("ld.html", page("<p>Events</p>", '<script type="application/ld+json">' + json.dumps(
        {"@type": "Patient", "name": NAME, "healthCondition": {"name": DX}}) + "</script>")),
    "url": ("link.html", page(f'<a href="/visit?name={NAME.replace(" ", "+")}&dx=G35">Visit</a>')),
    "page_title": ("title.html", f"<!doctype html><html><head><title>{LINE}</title></head><body>x</body></html>"),
    "web_storage": ("storage.html", page(f'<script>localStorage.setItem("last", "{LINE}");</script>')),
    "indexeddb": ("idb.html", page('<script>const r = indexedDB.open("v", 1); r.onsuccess = () => '
                                   'r.result.transaction("v", "readwrite").objectStore("v")'
                                   f'.put({{name: "{NAME}", dx: "{DX}"}});</script>')),
    "cookie": ("cookie.html", page(f'<script>document.cookie = "p={LINE}; path=/";</script>')),
    "third_party_request": ("pixel.html", page(
        f'<img src="https://px.tracker.example/p?n={NAME.replace(" ", "+")}&dx=G35" width="1">')),
    "response_header": ("_headers", f"/portal/visit\n  Set-Cookie: last={MRN}; Path=/\n"),
    "api_response": ("record.json", json.dumps({"name": NAME, "mrn": MRN, "condition": DX})),
    "data_file": ("export.csv", f"patient_name,mrn,diagnosis\n{NAME},{MRN},{DX}\n"),
    "error_surface": ("error.html", page(f"<h1>Error</h1><pre>KeyError: {LINE}</pre>")),
    "log": ("app.log", f"2026-01-04 INFO lookup patient={NAME} mrn={MRN} dx={DX}\n"),
    "pdf_text_layer": ("report.pdf", build_pdf([f"Patient: {LINE}"], {"Title": "Report"})),
    "document_metadata": ("template.docx", build_docx(["Template."], core={"creator": NAME, "subject": DX})),
    "tracked_changes": ("review.docx", build_docx(["Notes follow."], deleted=[LINE])),
    "hidden_sheet": ("roster.xlsx", build_xlsx([
        {"name": "Open", "rows": [["Clinic", "Room"]], "hidden": False},
        {"name": "Roster", "rows": [[NAME, DX]], "hidden": True}])),
    "speaker_notes": ("rounds.pptx", build_pptx([{"text": "Interesting cases", "notes": LINE}])),
    "exif": ("photo.jpg", build_jpeg({"ImageDescription": LINE})),
}

# Brief section 5 / PLAN G3: these must not be flagged.
HARD_NEGATIVES: dict[str, str] = {
    "valid NPI on a staff page": ("team/dr-wells.html", page(
        "<p>Dr. Anika Wells, MD - Neurology - NPI 1234567893</p>")),
    "lab reference ranges": ("ranges.html", page(
        "<table><tr><td>HbA1c</td><td>4.0-5.6 %</td></tr><tr><td>TSH</td><td>0.4-4.0 mIU/L</td></tr></table>")),
    "code-only page": ("codes.html", page("<p>G35 Multiple sclerosis</p><p>E11.9 Type 2 diabetes mellitus</p>")),
    "555-01xx phone": ("call.html", page("<p>Call our demo line on (617) 555-0123 about diabetes care.</p>")),
}


def main() -> int:
    src = OUT / "src"
    shutil.rmtree(OUT, ignore_errors=True)
    for path, body in list(CARRIERS.values()) + list(HARD_NEGATIVES.values()):
        target = src / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body if isinstance(body, bytes) else body.encode("utf-8"))
    collect(src, OUT / "run")
    findings = detect(OUT / "run" / "index.jsonl", OUT / "run" / "vault", (), context="public-web")
    vault = Vault(OUT / "run" / "vault")
    wanted = {vault.token(NAME), vault.token(MRN)}
    by_path: dict[str, list[dict]] = {}
    for finding in findings:
        by_path.setdefault(finding["path"], []).append(finding)

    problems = []
    print("CARRIER INVARIANCE")
    for carrier, (path, _) in CARRIERS.items():
        caught = any(wanted & set(f["value_hashes"]) for f in by_path.get(path, []))
        print(f"  {'ok  ' if caught else 'MISS'} {carrier:22} {path}")
        if not caught:
            problems.append(f"missed in {carrier}")
    print("HARD NEGATIVES")
    for label, (path, _) in HARD_NEGATIVES.items():
        flagged = by_path.get(path, [])
        print(f"  {'FLAG' if flagged else 'ok  '} {label}")
        if flagged:
            problems.append(f"flagged {label}")

    found = len(CARRIERS) - sum(p.startswith("missed") for p in problems)
    print(f"\ncarriers {found}/{len(CARRIERS)}, hard negatives clean "
          f"{len(HARD_NEGATIVES) - sum(p.startswith('flagged') for p in problems)}/{len(HARD_NEGATIVES)}")
    if problems:
        print(f"FAIL  {len(problems)} problem(s)")
        return 1
    print("PASS  the same finding is found in every carrier; hard negatives clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
