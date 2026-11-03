#!/usr/bin/env python3
"""Build the fake test world and its answer key.

Everything in here is invented. No real patient data is used or needed.

One generator is the single source of truth: it writes the fixtures AND the
answer key, so the two cannot disagree. Every planted value appears exactly once
inside the file it is claimed in, which makes its location unambiguous - the
checker relies on that. The same person can appear in two different files; that
is deliberate, because cross-file linking has to be tested later.

All personal values sit in ranges set aside for testing:
  - SSNs use 987-65-4330 to 4399: the ITIN-shaped space, still an identifier.
    987-65-4320 to 4329 is the advertising block and is a negative on purpose
  - phone numbers use the 555 exchange, which has no real subscribers
  - the site's domain ends in .example, reserved by RFC 2606

Run:  python fixtures/build_world.py
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from docgen import build_docx, build_jpeg, build_pdf, build_pptx, build_xlsx

ROOT = Path(__file__).resolve().parents[1]
WORLD = ROOT / "fixtures" / "world"
KEYS = ROOT / "eval" / "keys"
TRACKER_HOST = "127.0.0.1:8802"

FIRST = [
    "Marisol", "Desmond", "Priya", "Tobias", "Yuki", "Rosa", "Emeka", "Ingrid",
    "Hassan", "Beatrix", "Callum", "Nadia", "Osvaldo", "Freya", "Ravi", "Lucia",
    "Mateo", "Saoirse", "Kwame", "Elena", "Bartholomew", "Amara", "Soren", "Ivy",
    "Dmitri", "Tamsin", "Hiroshi", "Bianca", "Omar", "Greta", "Rafael", "Noor",
    "Pavel", "Aisha", "Lorenzo", "Maeve", "Kenji", "Sofia", "Idris", "Clara",
]
LAST = [
    "Quintanilla", "Achebe", "Raghunathan", "Lindqvist", "Tanabe", "Delgado",
    "Nwosu", "Solberg", "Al-Rashid", "Kovacs", "Ferreira", "Haddad", "Vasquez",
    "Nilsson", "Bhatt", "Moreau", "Castellanos", "O'Rourke", "Mensah", "Petrova",
    "Whitlock", "Okafor", "Halvorsen", "Lindgren", "Sokolov", "Ashworth",
    "Yamamoto", "Russo", "Farouk", "Schneider", "Ibarra", "Rahimi", "Novak",
    "Boateng", "Ricci", "Callaghan", "Watanabe", "Marchetti", "Bello", "Hoffmann",
]

DIAGNOSES = [
    ("invasive ductal carcinoma, stage IIIA", ["oncology"], "C50.911"),
    ("type 2 diabetes mellitus", [], "E11.9"),
    ("HIV-1 positive, on antiretroviral therapy", ["hiv"], "B20"),
    ("major depressive disorder, recurrent", ["mental_health"], "F33.1"),
    ("opioid use disorder, in remission", ["sud"], "F11.20"),
    ("BRCA1 c.5266dupC pathogenic variant", ["genetic", "oncology"], "Z15.01"),
    ("prenatal care, 28 weeks gestation", ["reproductive"], "Z34.90"),
    ("chronic kidney disease, stage 4", [], "N18.4"),
    ("relapsing-remitting multiple sclerosis", [], "G35"),
    ("chronic hepatitis C genotype 1a", [], "B18.2"),
]

DOCTORS = [
    ("Dr. Helena Marsh", "Medical Oncology", "1841290376"),
    ("Dr. Idris Bhandari", "Clinical Genetics", "1932415767"),
    ("Dr. Katarzyna Wolna", "Laboratory Medicine", "1073649281"),
]

claims: list[dict] = []
tags_by_value: dict[str, list[str]] = {}


def person(i: int) -> dict:
    first = FIRST[i % len(FIRST)]
    last = LAST[(i * 7 + 3) % len(LAST)]
    dx, tags, code = DIAGNOSES[i % len(DIAGNOSES)]
    return {
        "i": i,
        "name": f"{first} {last}",
        "mrn": f"MRN-{880000 + i * 137}",
        "dob": f"19{52 + i % 38}-{(i % 12) + 1:02d}-{(i % 27) + 1:02d}",
        "ssn": f"987-65-43{30 + i % 70:02d}",
        "phone": f"(617) 555-{2000 + i}",
        "email": f"{first.lower()}.{last.lower().replace(chr(39), '')}@northbridge.example",
        "dx": dx,
        "code": code,
        "tags": tags,
    }


def claim(file: str, carrier: str, record: str, value: str,
          level: str, ids: list[str], rules: list[str], note: str = "") -> None:
    claims.append({
        "file": file, "carrier": carrier, "record": record, "value": value,
        "expected_flag": True, "expected_level": level,
        "identifiers": ids, "sensitive": tags_by_value.get(value, []),
        "rules": rules, "note": note,
    })


def clean(file: str, carrier: str, record: str, value: str, note: str,
          level: str | None = None) -> None:
    claims.append({
        "file": file, "carrier": carrier, "record": record, "value": value,
        "expected_flag": False, "expected_level": level,
        "identifiers": [], "sensitive": [], "rules": [], "note": note,
    })


def write(rel: str, text: str) -> None:
    path = WORLD / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


def _dicom_element(group: int, element: int, vr: str, value) -> bytes:
    import struct

    if isinstance(value, str):
        value = value.encode("latin-1")
    if len(value) % 2:
        value += b"\x00" if vr == "UI" else b" "
    head = struct.pack("<HH", group, element) + vr.encode("ascii")
    if vr in ("OB", "OW", "OF", "SQ", "UT", "UN"):
        head += b"\x00\x00" + struct.pack("<I", len(value))
    else:
        head += struct.pack("<H", len(value))
    return head + value


def build_dicom(patient_name: str, patient_id: str, dob: str, study_date: str,
                description: str, diagnosis: str, physician: str) -> bytes:
    """A valid DICOM Part 10 file: 128-byte preamble, DICM, meta, dataset.

    Explicit VR, little endian. Header only, no pixel data, because the leak
    being tested is the metadata rather than the image.
    """
    import struct

    sop = "1.2.840.10008.5.1.4.1.1.2"
    instance = "1.2.826.0.1.3680043.8.498.1"
    meta = b""
    meta += _dicom_element(0x0002, 0x0001, "OB", b"\x00\x01")
    meta += _dicom_element(0x0002, 0x0002, "UI", sop)
    meta += _dicom_element(0x0002, 0x0003, "UI", instance)
    meta += _dicom_element(0x0002, 0x0010, "UI", "1.2.840.10008.1.2.1")
    meta += _dicom_element(0x0002, 0x0012, "UI", "1.2.826.0.1.3680043.8.498.2")
    meta += _dicom_element(0x0002, 0x0013, "SH", "PHISCAN")
    group_length = _dicom_element(0x0002, 0x0000, "UL", struct.pack("<I", len(meta)))

    dataset = b""
    dataset += _dicom_element(0x0008, 0x0016, "UI", sop)
    dataset += _dicom_element(0x0008, 0x0018, "UI", instance)
    dataset += _dicom_element(0x0008, 0x0020, "DA", study_date)
    dataset += _dicom_element(0x0008, 0x0060, "CS", "CT")
    dataset += _dicom_element(0x0008, 0x1030, "LO", description)
    dataset += _dicom_element(0x0008, 0x1050, "PN", physician)
    dataset += _dicom_element(0x0008, 0x1080, "LO", diagnosis)
    dataset += _dicom_element(0x0010, 0x0010, "PN", patient_name)
    dataset += _dicom_element(0x0010, 0x0020, "LO", patient_id)
    dataset += _dicom_element(0x0010, 0x0030, "DA", dob)
    dataset += _dicom_element(0x0010, 0x0040, "CS", "F")
    dataset += _dicom_element(0x0020, 0x000D, "UI", "1.2.826.0.1.3680043.8.498.3")
    return b"\x00" * 128 + b"DICM" + group_length + meta + dataset


def main() -> int:
    if WORLD.exists():
        shutil.rmtree(WORLD)
    WORLD.mkdir(parents=True, exist_ok=True)
    KEYS.mkdir(parents=True, exist_ok=True)

    p = [person(i) for i in range(40)]
    for q in p:
        for field in ("name", "mrn", "phone", "ssn", "email"):
            tags_by_value[q[field]] = q["tags"]

    # ---------------------------------------------------------------- pages
    write("site/index.html", """<!doctype html><html><head><title>Northbridge Health</title></head>
<body><h1>Northbridge Health</h1>
<p>Genomic and oncology care. Appointments: (617) 555-0142.</p>
<p>Contact us at info@northbridge.example or visit 400 Harbor Way, Boston, MA.</p>
<p>General information only. This page does not describe any patient.</p>
<nav><a href="/portal">Patient portal</a> <a href="/portal/visit">Check-in</a> <a href="/portal/lookup">Find a visit</a> <a href="/updates.html">Updates</a> <a href="/events.html">Events</a> <a href="/checkin.html">Kiosk</a> <a href="/portal-cache.html">Offline mode</a> <a href="/resources.html">Resources</a> <a href="/reports/annual-outcomes.html">Outcomes</a> <a href="/forms/sample-intake.html">Forms</a> <a href="/billing/codes.html">Billing</a> <a href="/stories/with-consent.html">Stories</a> <a href="/team.html">Team</a> <a href="/services.html">Services</a> <a href="/article.html">Article</a> <a href="/patient-story.html">Patient Story</a> <a href="/referrals.html">Referrals</a> <a href="/detail.html">Detail</a> <a href="/downloads.html">Downloads</a> <a href="/storage.html">Storage</a> <a href="/tracker.html">Tracker</a> <a href="/analytics.html">Analytics</a> <a href="/hidden.html">Hidden</a> <a href="/title.html">Title</a> <a href="/error.html">Error</a></nav></body></html>""")
    clean("site/index.html", "page_text", "contact_block", "info@northbridge.example",
          "Company contact block. Same domain as a patient email elsewhere, but this record is the organisation's own contact details.")

    team_rows = "\n".join(
        f"<li><strong>{n}</strong> - {spec} - NPI {npi}</li>" for n, spec, npi in DOCTORS)
    write("site/team.html", f"""<!doctype html><html><head><title>Our clinicians</title></head>
<body><h1>Our clinicians</h1><ul>{team_rows}</ul>
<p>All clinicians are board certified.</p></body></html>""")
    for n, spec, npi in DOCTORS:
        clean("site/team.html", "page_text", f"clinician_{npi}", npi,
              f"Valid provider identifier on a staff page for {n}. Staff profiles are not patient data.")

    write("site/article.html", """<!doctype html><html><head><title>Understanding genomic testing</title></head>
<body><h1>Understanding genomic testing</h1>
<p>Genomic testing looks for changes in your DNA. Results can guide treatment choices.</p>
<p>In 2024, about 12 percent of adults in the survey reported having had a genomic test.</p>
<p>Ask your clinician whether testing is right for you.</p></body></html>""")
    clean("site/article.html", "page_text", "article_lead", "Genomic testing looks for changes in your DNA",
          "Plain-language health article. No patient in a clinical role.")

    write("site/services.html", f"""<!doctype html><html><head><title>Services</title></head>
<body><h1>Services</h1><p>Oncology, genetics, laboratory medicine.</p>
<img src="http://{TRACKER_HOST}/pixel?page=services&amp;event=view" width="1" height="1" alt="">
</body></html>""")
    clean("site/services.html", "third_party", "analytics_pixel", "page=services",
          "A tracker call on a public page with no patient data. Review note, not a PHI finding.",
          level="review")

    write("site/patient-story.html", f"""<!doctype html><html><head><title>Patient stories</title></head>
<body><h1>Patient stories</h1>
<blockquote><p>{p[0]['name']}, diagnosed at 54 with {p[0]['dx']}, shares her experience.</p></blockquote>
<p>Read more patient stories.</p></body></html>""")
    claim("site/patient-story.html", "page_text", "testimonial", p[0]["name"],
          "critical", ["names", "dates"], ["permitted_disclosure"],
          "Public testimonial with a real-looking name and a cancer diagnosis. No consent marker on the page.")

    write("site/referrals.html", f"""<!doctype html><html><head><title>Referrals</title></head>
<body><h1>Open referrals</h1>
<ul>
<li><a href="/portal/patient?name={p[1]['name']}&amp;dx=B20">Open record</a></li>
<li><a href="/portal/patient?name={p[2]['name']}&amp;dx=F11.20">Open record</a></li>
<li><a href="/portal/patient?mrn={p[3]['mrn']}">Open record</a></li>
</ul></body></html>""")
    claim("site/referrals.html", "url", "referral_link_1", p[1]["name"],
          "critical", ["names", "url"], ["transmission_security"],
          "Patient name and HIV status in a link URL on a public page.")
    claim("site/referrals.html", "url", "referral_link_2", p[2]["name"],
          "critical", ["names", "url"], ["transmission_security", "part2_sud"],
          "Patient name and substance use disorder code in a link URL on a public page.")
    claim("site/referrals.html", "url", "referral_link_3", p[3]["mrn"],
          "critical", ["mrn", "url"], ["transmission_security"],
          "Medical record number in a link URL on a public page. Never-clearable class.")

    write("site/portal.html", f"""<!doctype html><html><head><title>Your portal</title></head>
<body><h1>Signed in as the test account</h1>
<section id="own">
<p>Your details: {p[4]['name']}, {p[4]['dob']}.</p>
<p>Your last visit: review of {p[4]['dx']}.</p>
</section>
<section id="other">
<h2>Record 1042</h2>
<p>{p[3]['name']} - {p[3]['mrn']} - {p[3]['dx']}</p>
</section></body></html>""")
    claim("site/portal.html", "page_text", "other_patient_block", p[3]["name"],
          "high", ["names", "mrn"], ["access_control_audit"],
          "Another patient's name, record number and diagnosis shown on an authenticated page.")
    clean("site/portal.html", "page_text", "own_record", p[4]["name"],
          "The account holder's own record. Own data is not a finding.")

    write("site/hidden.html", f"""<!doctype html><html><head><title>Care team</title></head>
<body><h1>Care team</h1>
<div style="display:none">{p[5]['name']} - {p[5]['dob']} - {p[5]['dx']}</div>
<!-- internal note: {p[5]['phone']} -->
<p>Our care team meets weekly.</p></body></html>""")
    claim("site/hidden.html", "hidden_code", "hidden_div", p[5]["name"],
          "critical", ["names", "dates"], ["permitted_disclosure"],
          "Patient name, date of birth and diagnosis in a hidden element.")
    claim("site/hidden.html", "hidden_code", "html_comment", p[5]["phone"],
          "high", ["phone"], ["permitted_disclosure"],
          "Patient phone number in an HTML comment.")

    write("site/title.html", f"""<!doctype html><html><head><title>Lab results for {p[6]['name']} - {p[6]['dx']}</title></head>
<body><h1>Routine lab results</h1><p>Please sign in to view your results.</p></body></html>""")
    claim("site/title.html", "title", "page_title", p[6]["name"],
          "critical", ["names"], ["permitted_disclosure"],
          "Patient name and diagnosis in the page title, which leaks into browser history and search results.")

    write("site/storage.html", f"""<!doctype html><html><head><title>Preferences</title></head>
<body><h1>Preferences</h1><p>Your display settings are remembered.</p>
<script>
localStorage.setItem('last_patient', JSON.stringify({{name: '{p[7]['name']}', mrn: '{p[7]['mrn']}', dx: '{p[7]['dx']}'}}));
</script></body></html>""")
    claim("site/storage.html", "browser_storage", "local_storage", p[7]["name"],
          "high", ["names", "mrn"], ["access_control_audit"],
          "Patient name, record number and diagnosis written to browser storage.")

    write("site/tracker.html", f"""<!doctype html><html><head><title>Thanks</title></head>
<body><h1>Thank you</h1>
<img src="http://{TRACKER_HOST}/collect?pid={p[8]['mrn']}&amp;dx=G35&amp;campaign=spring" width="1" height="1" alt="">
<p>We have received your form.</p></body></html>""")
    claim("site/tracker.html", "third_party", "tracker_payload", p[8]["mrn"],
          "critical", ["mrn"], ["transmission_security", "accounting_of_disclosures"],
          "A medical record number and a diagnosis code sent to an outside company in a tracking request.")

    write("site/error.html", f"""<!doctype html><html><head><title>Something went wrong</title></head>
<body><h1>Something went wrong</h1><pre>
Traceback (most recent call last):
  File "app/views.py", line 214, in patient_detail
    patient = {{"name": "{p[9]['name']}", "mrn": "{p[9]['mrn']}"}}
TypeError: 'NoneType' object is not subscriptable
</pre></body></html>""")
    claim("site/error.html", "error_surface", "stack_trace", p[9]["name"],
          "critical", ["names", "mrn"], ["activity_review"],
          "Error page exposes a patient record in a stack trace.")

    write("site/downloads.html", """<!doctype html><html><head><title>Downloads</title></head>
<body><h1>Files</h1>
<ul><li><a href="/files/roster.csv">Roster</a></li>
<li><a href="/files/lab-report.pdf">Lab report</a></li>
<li><a href="/files/export.json">Export</a></li></ul></body></html>""")
    clean("site/downloads.html", "page_text", "link_list", "/files/roster.csv",
          "A page of links only. The problem is inside the files, not here.")

    # ---------------------------------------------------------------- csv
    rows = ["patient_name,medical_record_number,date_of_birth,diagnosis,ssn"]
    for k in range(10):
        q = p[10 + k]
        rows.append(f"{q['name']},{q['mrn']},{q['dob']},{q['dx']},{q['ssn']}")
    write("files/roster.csv", "\n".join(rows) + "\n")
    for k in range(10):
        q = p[10 + k]
        claim("files/roster.csv", "downloadable_file", f"csv_row_{k + 1}", q["name"],
              "critical", ["names", "mrn", "dates", "ssn"], ["permitted_disclosure"],
              "One CSV row: name, record number, date of birth, diagnosis and SSN in the same record.")

    # ---------------------------------------------------------------- pdf
    pdf_lines = [
        "Northbridge Health - Laboratory Report",
        f"Patient: {p[20]['name']}   DOB: {p[20]['dob']}   MRN: {p[20]['mrn']}",
        f"Test: HbA1c   Result: 8.4 %   Flag: high   ({p[20]['dx']})",
        "",
        f"Patient: {p[21]['name']}   DOB: {p[21]['dob']}   MRN: {p[21]['mrn']}",
        f"Test: BRCA1 sequencing   Result: pathogenic variant detected   ({p[21]['dx']})",
        "",
        f"Patient: {p[22]['name']}   DOB: {p[22]['dob']}   MRN: {p[22]['mrn']}",
        f"Test: HIV-1 RNA   Result: 48 copies/mL   ({p[22]['dx']})",
    ]
    pdf = build_pdf(pdf_lines, {"Author": p[23]["name"], "Title": "Laboratory report",
                                "Producer": "Northbridge LIS"})
    (WORLD / "files").mkdir(parents=True, exist_ok=True)
    (WORLD / "files" / "lab-report.pdf").write_bytes(pdf)
    for k, idx in enumerate((20, 21, 22)):
        q = p[idx]
        claim("files/lab-report.pdf", "downloadable_file", f"pdf_result_{k + 1}", q["name"],
              "critical", ["names", "mrn", "dates"], ["permitted_disclosure"],
              "PDF text layer with name, date of birth, record number and a lab result.")
    claim("files/lab-report.pdf", "file_metadata", "pdf_info_author", p[23]["name"],
          "high", ["names"], ["permitted_disclosure"],
          "A patient name stored in the PDF document properties. Not visible on the page, but anyone opening the file can read it.")

    # ---------------------------------------------------------------- json
    export = [{"name": q["name"], "mrn": q["mrn"], "dob": q["dob"], "dx": q["dx"]}
              for q in (p[23], p[24], p[25], p[26], p[27])]
    write("files/export.json", json.dumps({"patients": export}, indent=2) + "\n")
    for k, idx in enumerate((23, 24, 25, 26, 27)):
        q = p[idx]
        claim("files/export.json", "downloadable_file", f"json_record_{k + 1}", q["name"],
              "critical", ["names", "mrn", "dates"], ["permitted_disclosure"],
              "One JSON record: identity and health detail in the same object.")

    # ---------------------------------------------------------------- api
    write("api/patient_1042.json", json.dumps({
        "resourceType": "Patient",
        "id": "1042",
        "name": [{"text": p[28]["name"]}],
        "birthDate": p[28]["dob"],
        "identifier": [{"system": "urn:northbridge:mrn", "value": p[28]["mrn"]}],
        "condition": [{"code": {"text": p[28]["dx"]}}],
    }, indent=2) + "\n")
    claim("api/patient_1042.json", "api_response", "patient_resource", p[28]["name"],
          "critical", ["names", "mrn", "dates"], ["permitted_disclosure"],
          "An API response returns a patient resource with no authentication check.")

    write("api/labs_1042.json", json.dumps({
        "resourceType": "Bundle",
        "patient": p[29]["name"],
        "entry": [
            {"code": "HbA1c", "value": "8.4 %", "flag": "high"},
            {"code": "eGFR", "value": "28 mL/min", "flag": "low"},
            {"code": "HIV-1 RNA", "value": "48 copies/mL", "flag": "high"},
        ],
    }, indent=2) + "\n")
    claim("api/labs_1042.json", "api_response", "lab_bundle", p[29]["name"],
          "critical", ["names"], ["permitted_disclosure", "part2_sud"],
          "An API response returns lab results next to a patient name.")

    write("api/health.json", json.dumps({"status": "ok", "version": "2.4.1"}, indent=2) + "\n")
    clean("api/health.json", "api_response", "health_check", "status",
          "Service health endpoint. No patient data.")

    # ---------------------------------------------------------------- logs
    log_lines = ["2026-10-01T09:12:44Z INFO  request_id=8f21 user=demo path=/portal"]
    for k in range(8):
        q = p[30 + k]
        log_lines.append(
            f"2026-10-01T09:{13 + k:02d}:02Z DEBUG patient_lookup mrn={q['mrn']} "
            f"name={q['name']} result={q['dx']}")
    write("logs/app.log", "\n".join(log_lines) + "\n")
    for k in range(8):
        q = p[30 + k]
        claim("logs/app.log", "log", f"log_line_{k + 1}", q["name"],
              "critical", ["names", "mrn"], ["activity_review"],
              "A debug log line with the patient's name, record number and diagnosis.")

    # ------------------------------------------- hidden, off the surface
    # None of these are readable by scrolling a page. They sit in metadata,
    # code, backups, a sitemap, and an encoded blob. This is the tier that a
    # text-only scanner will miss completely.
    import base64 as b64

    write("site/detail.html", f"""<!doctype html><html><head><title>Result detail</title>
<meta property="og:description" content="Results for {p[0]['name']} - {p[0]['dx']}">
</head>
<body data-patient='{{"name": "{p[1]['name']}", "mrn": "{p[1]['mrn']}"}}'>
<h1>Result detail</h1>
<p aria-label="{p[2]['name']}, {p[2]['dx']}">Summary</p>
<span style="position:absolute;left:-9999px;top:auto">{p[3]['name']} {p[3]['dob']}</span>
<p>Please contact the clinic with questions.</p></body></html>""")
    claim("site/detail.html", "meta_tag", "og_description", p[0]["name"],
          "critical", ["names"], ["permitted_disclosure"],
          "Patient name and diagnosis in the page's social-sharing metadata. Not visible on the page.")
    claim("site/detail.html", "html_attribute", "data_patient", p[1]["name"],
          "critical", ["names", "mrn"], ["permitted_disclosure"],
          "Patient name and record number inside a data attribute on the body tag.")
    claim("site/detail.html", "html_attribute", "aria_label", p[2]["name"],
          "critical", ["names"], ["permitted_disclosure"],
          "Patient name and diagnosis in an accessibility label.")
    claim("site/detail.html", "css_hidden", "offscreen_span", p[3]["name"],
          "high", ["names", "dates"], ["permitted_disclosure"],
          "Patient name and date of birth pushed off-screen by CSS. Still in the page, still readable.")

    write("site/analytics.html", f"""<!doctype html><html><head><title>Search</title></head>
<body><h1>Search</h1>
<script>window.__lastSearch = {{name: '{p[4]['name']}', dx: '{p[4]['dx']}'}};</script>
<p>Enter a term above.</p></body></html>""")
    claim("site/analytics.html", "inline_script", "last_search", p[4]["name"],
          "critical", ["names"], ["permitted_disclosure"],
          "Patient name and diagnosis written into an inline script variable.")

    blob = b64.b64encode(
        f"{p[6]['name']}|{p[6]['dob']}|{p[6]['dx']}".encode("utf-8")).decode("ascii")
    write("site/scripts/app.js", f"""const API_BASE = "/api/v1";
const SAMPLE_RECORD = {{"name": "{p[5]['name']}", "mrn": "{p[5]['mrn']}", "dx": "{p[5]['dx']}"}};
const CACHE_BLOB = "{blob}";
export {{ API_BASE, SAMPLE_RECORD, CACHE_BLOB }};
""")
    claim("site/scripts/app.js", "js_bundle", "sample_record", p[5]["name"],
          "critical", ["names", "mrn"], ["permitted_disclosure"],
          "A shipped JavaScript file contains a sample patient record.")
    claim("site/scripts/app.js", "encoded_value", "cache_blob", blob,
          "critical", ["names", "dates"], ["permitted_disclosure"],
          f'Base64 blob that decodes to "{p[6]["name"]}|{p[6]["dob"]}|{p[6]["dx"]}". Six characters of grep will not find this.')

    write("site/scripts/app.js.map", json.dumps({
        "version": 3,
        "file": "app.js",
        "sources": ["src/app.ts"],
        "sourcesContent": [
            f"// debug fixture left in the build\n"
            f"const DEBUG_PATIENT = '{p[7]['name']}|{p[7]['mrn']}|{p[7]['dx']}';\n"
        ],
    }, indent=2) + "\n")
    claim("site/scripts/app.js.map", "source_map", "sources_content", p[7]["name"],
          "critical", ["names", "mrn"], ["permitted_disclosure"],
          "The JavaScript source map still carries the original source with a hard-coded patient.")

    write("site/sitemap.xml", f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>https://northbridge.example/</loc></url>
<url><loc>https://northbridge.example/portal/patient?mrn={p[8]['mrn']}</loc></url>
<url><loc>https://northbridge.example/team</loc></url>
</urlset>
""")
    claim("site/sitemap.xml", "sitemap", "indexed_url", p[8]["mrn"],
          "critical", ["mrn", "url"], ["transmission_security"],
          "A medical record number sits in a URL the sitemap hands to search engines.")

    write("site/backup/db_dump.sql", f"""-- nightly export, left in the web root
CREATE TABLE patients (id INT, name TEXT, mrn TEXT, dob TEXT, dx TEXT);
INSERT INTO patients VALUES (1, '{p[9]['name']}', '{p[9]['mrn']}', '{p[9]['dob']}', '{p[9]['dx']}');
INSERT INTO patients VALUES (2, '{p[10]['name']}', '{p[10]['mrn']}', '{p[10]['dob']}', '{p[10]['dx']}');
""")
    claim("site/backup/db_dump.sql", "unlinked_file", "insert_1", p[9]["name"],
          "critical", ["names", "mrn", "dates"], ["permitted_disclosure"],
          "A database dump sitting in a web folder. Nothing links to it, but anyone can guess the path.")
    claim("site/backup/db_dump.sql", "unlinked_file", "insert_2", p[10]["name"],
          "critical", ["names", "mrn", "dates"], ["permitted_disclosure"],
          "Second row of the same database dump.")

    write("site/backup/index.html", """<!doctype html><html><head><title>Index of /backup</title></head>
<body><h1>Index of /backup</h1>
<ul><li><a href="db_dump.sql">db_dump.sql</a></li></ul></body></html>""")

    write("site/exports/patients_2026-09.csv",
          "name,mrn,dx\n"
          f"{p[11]['name']},{p[11]['mrn']},{p[11]['dx']}\n"
          f"{p[12]['name']},{p[12]['mrn']},{p[12]['dx']}\n")
    claim("site/exports/patients_2026-09.csv", "unlinked_file", "export_row_1", p[11]["name"],
          "critical", ["names", "mrn"], ["permitted_disclosure"],
          "A monthly patient export left in a folder that no page links to.")
    claim("site/exports/patients_2026-09.csv", "unlinked_file", "export_row_2", p[12]["name"],
          "critical", ["names", "mrn"], ["permitted_disclosure"],
          "Second row of the same unlinked export.")

    write("site/.env", f"""DB_URL=postgres://app:example-not-a-real-secret@localhost/northbridge
DEMO_PATIENT_NAME={p[13]['name']}
DEMO_PATIENT_MRN={p[13]['mrn']}
""")
    claim("site/.env", "env_file", "demo_patient", p[13]["name"],
          "critical", ["names", "mrn"], ["permitted_disclosure"],
          "A environment file published in the web root, with a patient name and record number in it.")

    # ------------------------------------- discovery and build leftovers
    # These are not hidden in the page. They are the surfaces a stranger uses
    # to FIND the leaks, plus the files a build pipeline forgets to remove.

    write("site/robots.txt", f"""User-agent: *
Disallow: /backup/
Disallow: /exports/
Disallow: /portal/patient?mrn={p[14]['mrn']}
""")
    claim("site/robots.txt", "robots_txt", "disallow_mrn", p[14]["mrn"],
          "critical", ["mrn", "url"], ["transmission_security"],
          "A record number written into robots.txt. The file is public, and it points straight at the record.")

    write("site/.git/config", """[core]
\trepositoryformatversion = 0
[remote "origin"]
\turl = https://deploy:example-token@git.northbridge.example/nbhc/portal.git
""")
    write("site/.git/COMMIT_EDITMSG",
          f"fix: correct date of birth for {p[15]['name']} ({p[15]['mrn']})\n")
    claim("site/.git/COMMIT_EDITMSG", "git_exposure", "commit_message", p[15]["name"],
          "critical", ["names", "mrn"], ["permitted_disclosure"],
          "A git folder left in the web root. Commit messages routinely name patients and record numbers.")

    write("site/swagger.json", json.dumps({
        "openapi": "3.0.1",
        "info": {"title": "Northbridge API", "version": "2.4.1"},
        "paths": {"/v1/patients/{id}": {"get": {"responses": {"200": {"content": {
            "application/json": {"example": {
                "name": p[16]["name"],
                "mrn": p[16]["mrn"],
                "diagnosis": p[16]["dx"],
            }}}}}}}},
    }, indent=2) + "\n")
    claim("site/swagger.json", "api_docs", "example_response", p[16]["name"],
          "critical", ["names", "mrn"], ["permitted_disclosure"],
          "Published API documentation uses a real patient as the example response.")

    write("site/print.css",
          '@media print { .receipt::after { content: "'
          + p[17]["name"] + " " + p[17]["dob"] + '"; } }\n')
    claim("site/print.css", "print_css", "print_only_content", p[17]["name"],
          "high", ["names", "dates"], ["permitted_disclosure"],
          "Patient name and date of birth in a print-only stylesheet rule. Invisible on screen, appears on paper.")

    # ------------------------------------------------ clinical file formats
    # FHIR: patient and condition are separate resources in one bundle, joined
    # only by a reference. Neither resource alone says "this person has this".
    patient = p[38]
    given, family = patient["name"].split(" ", 1)
    bundle = {
        "resourceType": "Bundle",
        "type": "collection",
        "entry": [
            {"fullUrl": "urn:uuid:pat-1", "resource": {
                "resourceType": "Patient", "id": "1042",
                "name": [{"use": "official", "text": patient["name"],
                          "family": family, "given": [given]}],
                "birthDate": patient["dob"],
                "identifier": [{"system": "urn:northbridge:mrn", "value": patient["mrn"]}],
            }},
            {"fullUrl": "urn:uuid:obs-1", "resource": {
                "resourceType": "Observation", "id": "obs-1", "status": "final",
                "subject": {"reference": "urn:uuid:pat-1"},
                "code": {"text": "HbA1c"},
                "valueQuantity": {"value": 9.1, "unit": "%"},
            }},
            {"fullUrl": "urn:uuid:cond-1", "resource": {
                "resourceType": "Condition", "id": "cond-1",
                "subject": {"reference": "urn:uuid:pat-1"},
                "code": {"text": patient["dx"]},
            }},
        ],
    }
    write("site/fhir/bundle_1042.json", json.dumps(bundle, indent=2) + "\n")
    claim("site/fhir/bundle_1042.json", "fhir_resource", "bundle_patient", patient["name"],
          "critical", ["names", "mrn", "dates"], ["permitted_disclosure"],
          "A FHIR bundle where the Patient and the Condition are separate resources linked only by a reference. Finding this means resolving the reference, not reading one resource.")

    # DICOM: identifiers live in the header, not in the picture.
    study = p[39]
    dicom = build_dicom(
        patient_name=study["name"],
        patient_id=study["mrn"],
        dob=study["dob"].replace("-", ""),
        study_date="20260114",
        description="CT ABDOMEN WITH CONTRAST",
        diagnosis="pancreatic carcinoma with hepatic metastases",
        physician=DOCTORS[0][0],
    )
    (WORLD / "site" / "dicom").mkdir(parents=True, exist_ok=True)
    (WORLD / "site" / "dicom" / "study.dcm").write_bytes(dicom)
    claim("site/dicom/study.dcm", "dicom_header", "patient_name", study["name"],
          "critical", ["names", "mrn", "dates"], ["permitted_disclosure"],
          "A DICOM study header carrying the patient's name, record number, date of birth and the diagnosis. The image itself is untouched; the leak is the metadata.")

    # ------------------------------------------------- live-site carriers
    # Everything below is served by fixtures/serve.py with two provisioned test
    # accounts. Headers and redirects live in Netlify-style _headers and
    # _redirects files, so each planted header still has one byte offset.
    account_a, account_b = p[30], p[31]
    for who in (account_a, account_b):
        write(f"api/v2/patients/{who['i']}.json", json.dumps({
            "resourceType": "Patient", "id": str(who["i"]),
            "name": [{"text": who["name"]}],
            "identifier": [{"system": "urn:northbridge:mrn", "value": who["mrn"]}],
            "birthDate": who["dob"],
            "condition": who["dx"],
        }, indent=2) + "\n")
    clean(f"api/v2/patients/{account_a['i']}.json", "api_response", "own_record", account_a["name"],
          "Account A's own record, read while logged in as account A. Own data is not a finding.")
    claim(f"api/v2/patients/{account_b['i']}.json", "api_response", "idor_record", account_b["name"],
          "high", ["names", "mrn", "dates"], ["permitted_disclosure", "access_control_audit"],
          "Account B's record, readable by account A by changing the id in the URL: an IDOR.")

    write("api/v2/openapi.json", json.dumps({
        "openapi": "3.0.3", "info": {"title": "Northbridge patient API", "version": "2"},
        "paths": {
            "/api/v2/patients/me": {"get": {"summary": "The logged-in patient's record"}},
            "/api/v2/patients/{id}": {"get": {"summary": "A patient record by id",
                                               "parameters": [{"name": "id", "in": "path",
                                                               "required": True}]}},
        },
    }, indent=2) + "\n")
    write("site/portal/visit.html", """<!doctype html><html><head><title>Your visit</title></head>
<body><h1>Your visit</h1><p>Your check-in is complete.</p></body></html>""")

    cookie_patient, redirect_patient, public_print = p[32], p[33], p[34]
    write("site/_headers", f"""/portal/visit
  Set-Cookie: last_patient={cookie_patient['mrn']}; Path=/
/portal/print/*
  Cache-Control: public, max-age=86400
""")
    claim("site/_headers", "response_header", "set_cookie", cookie_patient["mrn"],
          "high", ["mrn"], ["permitted_disclosure"],
          "A record number set as a cookie on every visit page. It travels in every request.")
    write("site/_redirects",
          f"/portal/lookup  /portal/print/visit-summary?mrn={redirect_patient['mrn']}"
          f"&dx={redirect_patient['code']}  302\n")
    claim("site/_redirects", "response_header", "location", redirect_patient["mrn"],
          "high", ["mrn"], ["permitted_disclosure"],
          "A redirect whose Location carries a record number and a diagnosis code.")
    write("site/portal/print/visit-summary.html", f"""<!doctype html><html><head><title>Visit summary</title></head>
<body><h1>Visit summary</h1>
<p>{public_print['name']} was seen for {public_print['dx']}.</p></body></html>""")
    claim("site/portal/print/visit-summary.html", "page_text", "print_summary", public_print["name"],
          "critical", ["names"], ["permitted_disclosure"],
          "Under /portal but served without a login. The path suggests private; the logged-out re-fetch proves public.")

    aria, ld, idb, cookie_js = p[35], p[36], p[37], p[18]
    write("site/updates.html", f"""<!doctype html><html><head><title>Clinic updates</title></head>
<body><h1>Clinic updates</h1><p>New parking opens in March.</p>
<span aria-hidden="true">{aria['name']} - {aria['dx']}</span></body></html>""")
    claim("site/updates.html", "aria_hidden", "screen_reader_hidden", aria["name"],
          "critical", ["names"], ["permitted_disclosure"],
          "Text hidden from screen readers but present in the page for anyone who views source.")
    write("site/events.html", f"""<!doctype html><html><head><title>Community events</title>
<script type="application/ld+json">{json.dumps({
        "@context": "https://schema.org", "@type": "Patient", "name": ld["name"],
        "healthCondition": {"@type": "MedicalCondition", "name": ld["dx"]}})}</script>
</head><body><h1>Community events</h1><p>Health fair on Saturday.</p></body></html>""")
    claim("site/events.html", "json_ld", "structured_data", ld["name"],
          "critical", ["names"], ["permitted_disclosure"],
          "Structured data for search engines describing a patient and their condition.")
    write("site/portal-cache.html", f"""<!doctype html><html><head><title>Loading</title></head>
<body><script>
const open = indexedDB.open("visits", 1);
open.onupgradeneeded = () => open.result.createObjectStore("visits", {{autoIncrement: true}});
open.onsuccess = () => open.result.transaction("visits", "readwrite")
  .objectStore("visits").put({{mrn: "{idb['mrn']}", dx: "{idb['code']}"}});
</script></body></html>""")
    claim("site/portal-cache.html", "indexeddb", "visit_cache", idb["mrn"],
          "high", ["mrn"], ["permitted_disclosure"],
          "A record number and diagnosis code written into the browser's IndexedDB.")
    write("site/checkin.html", f"""<!doctype html><html><head><title>Check in</title></head>
<body><h1>Check in</h1><script>
document.cookie = "checkin=" + encodeURIComponent("{cookie_js['name']}|{cookie_js['code']}") + "; path=/";
</script></body></html>""")
    claim("site/checkin.html", "cookie", "checkin_cookie", cookie_js["name"],
          "high", ["names"], ["permitted_disclosure"],
          "A script-set cookie holding a name and a diagnosis code.")

    # ------------------------------------------------- document carriers
    # The places a word processor or camera hides text. Four new people, because
    # person(i) repeats names past 40. Containers are stored uncompressed, so
    # each planted value still has one byte offset in the file.
    extra = []
    for i, name in zip(range(40, 44), ("Thandiwe Okonkwo", "Lars Eriksen",
                                        "Mei-Ling Zhao", "Gustavo Pereira")):
        who = person(i)
        who["name"] = name
        tags_by_value[name] = who["tags"]
        extra.append(who)
    roster, tracked, meta, notes, photo = p[19], *extra
    (WORLD / "files").mkdir(parents=True, exist_ok=True)
    (WORLD / "files" / "intake-roster.xlsx").write_bytes(build_xlsx([
        {"name": "Schedule", "rows": [["Clinic", "Room"], ["Oncology", "3"]], "hidden": False},
        {"name": "Roster", "rows": [["Name", "Condition"], [roster["name"], roster["dx"]]],
         "hidden": True}]))
    claim("files/intake-roster.xlsx", "hidden_sheet", "roster_row", roster["name"],
          "critical", ["names"], ["permitted_disclosure"],
          "A hidden worksheet. Excel does not show it; anyone who unhides it, or reads the file, does.")
    (WORLD / "files" / "case-review.docx").write_bytes(build_docx(
        ["Case review for the tumour board.", "Discussion notes follow."],
        deleted=[f"{tracked['name']} - {tracked['dx']}"]))
    claim("files/case-review.docx", "tracked_changes", "deleted_text", tracked["name"],
          "critical", ["names"], ["permitted_disclosure"],
          "Deleted with track changes on. The deletion is still in the file.")
    (WORLD / "files" / "discharge-template.docx").write_bytes(build_docx(
        ["Discharge instructions template."], core={"creator": meta["name"], "subject": meta["dx"]}))
    claim("files/discharge-template.docx", "file_metadata", "core_properties", meta["name"],
          "critical", ["names"], ["permitted_disclosure"],
          "A blank template whose document properties still name the patient it was made from.")
    (WORLD / "files" / "grand-rounds.pptx").write_bytes(build_pptx([
        {"text": "Grand rounds: interesting cases", "notes": f"{notes['name']}, {notes['dx']}"}]))
    claim("files/grand-rounds.pptx", "speaker_notes", "presenter_notes", notes["name"],
          "critical", ["names"], ["permitted_disclosure"],
          "Speaker notes are not on the slide, but they are in the file that was published.")
    (WORLD / "files" / "wound-photo.jpg").write_bytes(build_jpeg(
        {"ImageDescription": f"{photo['name']} - {photo['dx']}", "Software": "ClinicCam 2.1"}))
    claim("files/wound-photo.jpg", "exif", "image_description", photo["name"],
          "critical", ["names"], ["permitted_disclosure"],
          "A clinical photo whose EXIF caption names the patient and the condition.")
    write("site/resources.html", """<!doctype html><html><head><title>Resources</title></head>
<body><h1>Resources</h1><ul>
<li><a href="/files/intake-roster.xlsx">Clinic schedule</a></li>
<li><a href="/files/case-review.docx">Tumour board template</a></li>
<li><a href="/files/discharge-template.docx">Discharge template</a></li>
<li><a href="/files/grand-rounds.pptx">Grand rounds slides</a></li>
<li><a href="/files/wound-photo.jpg">Photo guidance</a></li>
</ul></body></html>""")

    # ------------------------------------------------- negative predicates
    # policy/negatives.yaml names a fixture for each; these are the four the
    # original world did not already have.
    write("site/reports/annual-outcomes.html", """<!doctype html><html><head><title>Annual outcomes</title></head>
<body><h1>2025 outcomes</h1>
<p>We treated 1,214 patients for type 2 diabetes; 87% reached their HbA1c target.</p>
<p>312 patients completed cardiac rehabilitation.</p></body></html>""")
    clean("site/reports/annual-outcomes.html", "page_text", "group_count", "1,214 patients",
          "Counts about groups of 11 or more. No person is described.")
    write("site/forms/sample-intake.html", """<!doctype html><html><head><title>Sample intake form</title></head>
<body><h1>SAMPLE - intake form</h1>
<p>SSN: 000-12-3456 &middot; Phone: (617) 555-0123 &middot; Email: sample.patient@example.com</p></body></html>""")
    clean("site/forms/sample-intake.html", "page_text", "sample_values", "000-12-3456",
          "Reserved values only: SSN area 000, phone 555-0123, an example.com address.")
    write("site/billing/codes.html", """<!doctype html><html><head><title>Billing codes</title></head>
<body><h1>Common codes</h1><table>
<tr><td>E11.9</td><td>Type 2 diabetes mellitus without complications</td></tr>
<tr><td>Z34.90</td><td>Encounter for supervision of normal pregnancy</td></tr>
</table></body></html>""")
    clean("site/billing/codes.html", "page_text", "code_table", "E11.9",
          "A code reference table. No person is attached to any code.")
    write("site/stories/with-consent.html", """<!doctype html><html><head><title>Patient stories</title></head>
<body><h1>Stories</h1>
<p>Rosalind Achterberg talks about life after her kidney transplant.
<em>Shared with Rosalind's written permission.</em></p></body></html>""")
    clean("site/stories/with-consent.html", "page_text", "consented_story", "Rosalind Achterberg",
          "A testimonial with a visible consent marker in the same record.")

    # ---------------------------------------------------------------- key
    items: list[dict] = []
    for index, entry in enumerate(claims, start=1):
        path = WORLD / entry["file"]
        if not path.exists():
            raise SystemExit(f"claimed file does not exist: {entry['file']}")
        data = path.read_bytes()
        needle = entry["value"].encode("utf-8")
        count = data.count(needle)
        if count != 1:
            raise SystemExit(
                f"{entry['value']!r} appears {count} times in {entry['file']}, expected exactly 1")
        items.append({
            "id": f"{'L' if entry['expected_flag'] else 'C'}{index:03d}",
            **entry,
            "offset": data.find(needle),
            "bytes": len(data),
        })

    flagged = [i for i in items if i["expected_flag"]]
    carriers = sorted({i["carrier"] for i in flagged})
    key = {
        "version": 1,
        "generator": "fixtures/build_world.py",
        "world_root": "fixtures/world",
        "counts": {"flagged": len(flagged), "clean": len(items) - len(flagged),
                   "carriers": len(carriers)},
        "carriers": carriers,
        "items": items,
    }
    key_text = json.dumps(key, indent=2, sort_keys=True) + "\n"
    key_path = KEYS / "world_key.json"
    # newline="\n": the frozen hash is over the file's bytes, which must not
    # depend on the operating system that built it.
    key_path.write_text(key_text, encoding="utf-8", newline="\n")
    digest = hashlib.sha256(key_text.encode("utf-8")).hexdigest()

    print(f"built world at {WORLD}")
    print(f"  flagged items : {len(flagged)}")
    print(f"  clean items   : {len(items) - len(flagged)}")
    print(f"  carriers      : {len(carriers)}  {', '.join(carriers)}")
    print(f"  answer key    : {key_path}")
    print(f"  key sha256    : {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
