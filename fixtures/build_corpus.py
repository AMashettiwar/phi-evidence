#!/usr/bin/env python3
"""Build the evaluation corpus and its answer key.

build_world.py is a hand-written demo site: a few dozen planted values, each
chosen by a person. That is too small and too easy to tune against, so this
generator produces the exam itself: 1,680 single-file items, every one with
exactly one thing to decide.

  - 960 positives in six strata (prose, structured records, web carriers,
    documents, always-flag identifiers alone, obfuscated values), each with one
    exposure record and nothing else that looks like an identifier;
  - 720 negatives in eight strata, one per situation in policy/negatives.yaml
    plus "identity without health", each built to tempt a naive detector.

One generator writes the files AND the key, so they cannot disagree. Every item
carries the exact bytes (`raw`) and byte offset of its planted value, and the
build aborts if the value is not found exactly once at that offset. Every fifth
item in a stratum is "heldout": tune on dev, report on heldout, never look
twice.

Everything is invented. Reserved ranges are used wherever a value must be fake:
.example hosts, 555-01xx phones, SSA-invalid SSNs, RFC 5737 addresses.
Positive SSNs, by contrast, are structurally VALID on purpose (a scanner that
validates them must still flag them); they are random digits, not anyone's.

Deterministic: one seeded Random and one seeded Faker, so two builds give
byte-identical files and key.

Run:  python fixtures/build_corpus.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import re
import shutil
import sys
from pathlib import Path
from urllib.parse import quote, quote_plus

from faker import Faker

sys.path.insert(0, str(Path(__file__).resolve().parent))
import docgen  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SEED = 20261102
CARRIERS = {
    "visible_text", "html_comment", "css_hidden", "aria_hidden", "data_attribute",
    "json_ld", "url", "page_title", "response_header", "web_storage", "indexeddb",
    "cookie", "api_response", "third_party_request", "data_file", "pdf_text_layer",
    "document_metadata", "exif", "hidden_sheet", "tracked_changes", "speaker_notes",
    "error_surface", "log",
}
EXT = {"html": "html", "txt": "txt", "json": "json", "hl7": "hl7", "csv": "csv",
       "x12": "x12", "pdf": "pdf", "docx": "docx", "xlsx": "xlsx", "pptx": "pptx",
       "jpeg": "jpg", "log": "log"}

# ------------------------------------------------------------------ pools
# No commas, quotes, ampersands or brackets in any health string: they are
# dropped into CSV cells, JS strings, HTML and PDF text without escaping, because
# escaping would change the bytes that `raw` promises.
HEALTH = [
    ("invasive ductal carcinoma stage IIIA", "C50.911", ["oncology"]),
    ("prostate cancer under active surveillance", "C61", ["oncology"]),
    ("non-small cell lung cancer", "C34.90", ["oncology"]),
    ("colon adenocarcinoma", "C18.9", ["oncology"]),
    ("acute lymphoblastic leukemia", "C91.00", ["oncology"]),
    ("HIV-1 infection on antiretroviral therapy", "B20", ["hiv"]),
    ("HIV preexposure prophylaxis follow-up", "Z21", ["hiv"]),
    ("major depressive disorder recurrent", "F33.1", ["mental_health"]),
    ("generalized anxiety disorder", "F41.1", ["mental_health"]),
    ("schizophrenia on clozapine", "F20.9", ["mental_health"]),
    ("bipolar disorder type I", "F31.9", ["mental_health"]),
    ("opioid use disorder in remission", "F11.21", ["sud"]),
    ("alcohol dependence on naltrexone", "F10.20", ["sud"]),
    ("stimulant use disorder", "F15.20", ["sud"]),
    ("prenatal care at 28 weeks gestation", "Z34.90", ["reproductive"]),
    ("female infertility under evaluation", "N97.9", ["reproductive"]),
    ("termination of pregnancy counselling", "Z31.69", ["reproductive"]),
    ("BRCA1 pathogenic variant carrier", "Z15.01", ["genetic", "oncology"]),
    ("cystic fibrosis F508del homozygous", "E84.0", ["genetic"]),
    ("Huntington disease", "G10", ["genetic"]),
    ("type 2 diabetes mellitus", "E11.9", []),
    ("essential hypertension", "I10", []),
    ("moderate persistent asthma", "J45.40", []),
    ("chronic kidney disease stage 4", "N18.4", []),
    ("relapsing-remitting multiple sclerosis", "G35", []),
    ("chronic hepatitis C genotype 1a", "B18.2", []),
    ("chronic low back pain", "M54.5", []),
    ("gastro-oesophageal reflux disease", "K21.9", []),
    ("hyperlipidaemia on atorvastatin", "E78.5", []),
    ("chronic obstructive pulmonary disease", "J44.9", []),
    ("atrial fibrillation on apixaban", "I48.91", []),
    ("rheumatoid arthritis on methotrexate", "M06.9", []),
    ("plaque psoriasis", "L40.0", []),
    ("migraine without aura", "G43.009", []),
    ("primary open-angle glaucoma", "H40.119", []),
    ("hypothyroidism on levothyroxine", "E03.9", []),
]
FIRST_EXTRA = ["José", "Zoë", "Chloé", "Priya", "Yuki", "Emeka", "Ingrid", "Hassan", "Nadia",
               "Osvaldo", "Kwame", "Saoirse", "Amara", "Soren", "Hiroshi", "Noor", "Idris", "Mateo"]
LAST_EXTRA = ["Nuñez", "Müller", "Hernández", "Achebe", "Raghunathan", "Nwosu", "Al-Rashid",
              "Tanabe", "Quintanilla", "Lindqvist", "Okafor", "Mensah", "Petrova", "Bhatt", "Kovacs"]
FILLER = [
    "Please contact the front desk with any questions.",
    "This page is updated by the communications team.",
    "Opening hours are listed on the main page.",
    "Thank you for visiting our community site.",
    "All content is provided for general information.",
    "Parking is available behind the main building.",
    "Our volunteers meet in the common room.",
]
SPECIALTIES = ["Cardiology", "Medical Oncology", "Family Medicine", "Neurology", "Dermatology",
               "Orthopaedic Surgery", "Endocrinology", "Paediatrics", "Psychiatry", "Radiology"]
ORG_A = ["Harbor", "Cedar", "Summit", "Lakeview", "Northgate", "Riverbend", "Oakridge",
         "Willowbrook", "Fairmont", "Stonebridge"]
ORG_B = ["Medical Group", "Health Partners", "Family Clinic", "Imaging Center", "Care Network"]
CONSENT = ["Shared with written permission", "Names and details changed",
           "Dramatisation based on composite cases", "Published with the person's consent",
           "Fictional account"]
ICD = [(c, d) for d, c, _ in HEALTH]
CPT = [("99213", "Office visit established patient"), ("93000", "Electrocardiogram complete"),
       ("80053", "Comprehensive metabolic panel"), ("85025", "Complete blood count"),
       ("36415", "Routine venipuncture"), ("71046", "Chest X-ray two views"),
       ("45378", "Colonoscopy diagnostic"), ("90471", "Immunization administration"),
       ("97110", "Therapeutic exercise"), ("99395", "Preventive visit established patient")]
LOINC = [("4548-4", "Hemoglobin A1c"), ("2093-3", "Cholesterol total"), ("718-7", "Hemoglobin"),
         ("2345-7", "Glucose serum"), ("2160-0", "Creatinine serum"), ("3016-3", "Thyrotropin"),
         ("6690-2", "Leukocytes count"), ("777-3", "Platelets count"), ("13457-7", "LDL calculated")]
DIGIT_WORDS = "zero one two three four five six seven eight nine".split()
HOMOGLYPH = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с",
             "x": "х", "y": "у"}
TECHNIQUES = ["zero_width", "homoglyph", "base64", "html_entities", "rtl", "split_nodes",
              "spelled_out", "digit_substitution"]
SAFE_WORD = re.compile(r"^[^\W\d_]+(?:-[^\W\d_]+)*$")

_rng: random.Random
_fake: Faker
_out: Path
_items: list[dict]


# ------------------------------------------------------------------ values
def pick_name(ascii_only: bool = False) -> tuple[str, str]:
    """First and last name; letters only, so no escaping can alter them."""
    while True:
        first = _rng.choice(FIRST_EXTRA) if _rng.random() < 0.25 else _fake.first_name()
        last = _rng.choice(LAST_EXTRA) if _rng.random() < 0.25 else _fake.last_name()
        if SAFE_WORD.match(first) and SAFE_WORD.match(last) \
                and not (ascii_only and not (first + last).isascii()):
            return first, last


def digits(n: int) -> str:
    return "".join(_rng.choice("0123456789") for _ in range(n))


def mrn(dash: bool = False) -> str:
    form = 0 if dash else _rng.randrange(3)
    return [f"MRN-{_rng.randint(100000, 999999)}", f"MRN: 00{_rng.randint(100000, 999999)}",
            f"Medical Record #: {_rng.randint(1000000, 9999999)}"][form]


def ssn() -> str:
    """Structurally valid: area 001-665 or 667-899, group 01-99, serial 0001-9999."""
    area = _rng.choice([a for a in range(1, 900) if a != 666])
    return f"{area:03d}-{_rng.randint(1, 99):02d}-{_rng.randint(1, 9999):04d}"


def reserved_ssn() -> str:
    kind = _rng.randrange(5)
    group, serial = _rng.randint(1, 99), _rng.randint(1, 9999)
    return [f"000-{group:02d}-{serial:04d}", f"666-{group:02d}-{serial:04d}",
            f"{_rng.randint(1, 665):03d}-00-{serial:04d}",
            f"{_rng.randint(1, 665):03d}-{group:02d}-0000",
            f"987-65-43{_rng.randint(20, 29)}"][kind]


def plan_id(plain: bool = False) -> str:
    """A labelled member ID, or a Medicare MBI following the CMS character rules."""
    if _rng.random() < 0.5:
        ident = "".join(_rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(3)) + digits(9)
        return ident if plain else f"Member ID: {ident}"
    letter, alnum = "ACDEFGHJKMNPQRTUVWXY", "ACDEFGHJKMNPQRTUVWXY0123456789"
    c = _rng.choice
    ident = (c("123456789") + c(letter) + c(alnum) + c("0123456789") + c(letter) + c(alnum)
             + c("0123456789") + c(letter) + c(letter) + c("0123456789") + c("0123456789"))
    return ident if plain else f"MBI: {ident}"


def always_id(kind: str, plain: bool = False) -> str:
    return {"ssn": ssn, "mrn": lambda: mrn(plain), "plan_id": lambda: plan_id(plain)}[kind]()


def phone() -> str:
    return f"{_rng.randint(2, 9)}{digits(2)}-555-{_rng.randint(2000, 9999)}"


def reserved(kind: str) -> str:
    if kind == "ssn":
        return reserved_ssn()
    if kind == "phone":
        return f"{_rng.randint(2, 9)}{digits(2)}-555-{_rng.randint(100, 199):04d}"
    if kind == "email":
        return (_rng.choice(["sample.user", "test.patient", "jdoe", "demo.account"]) + "@"
                + _rng.choice(["example.com", "example.net", "example.org", "mail.test",
                               "clinic.example", "demo.invalid"]))
    net = _rng.choice(["192.0.2", "198.51.100", "203.0.113"])
    return f"{net}.{_rng.randint(1, 254)}"


def luhn_npi() -> str:
    """NPI: 9 digits plus a Luhn check digit computed over the 80840 prefix."""
    body = str(_rng.randint(1, 2)) + digits(8)
    total = 0
    for i, ch in enumerate(reversed("80840" + body)):
        d = int(ch) * (2 if i % 2 == 0 else 1)
        total += d - 9 if d > 9 else d
    return body + str((10 - total % 10) % 10)


def filler() -> str:
    return _rng.choice(FILLER)


def health() -> tuple[str, str, list[str]]:
    return _rng.choice(HEALTH)


def page(body: str, title: str = "Community health notes", head: str = "") -> str:
    return (f'<!doctype html><html><head><meta charset="utf-8"><title>{title}</title>{head}'
            f"</head><body>{body}</body></html>\n")


# ------------------------------------------------------------------ emit
def add(stratum: str, k: int, template: str, fmt: str, carrier: str, content: str | bytes,
        raw: str, value: str, ids: list[str], *, hl: str | None = None,
        tags: list[str] | None = None, obf: str = "none", predicate: str | None = None,
        expected: bool = True, always: bool = False) -> None:
    """Write one item file and record it, enforcing the offset/raw invariant."""
    assert carrier in CARRIERS, carrier
    item_id = f"{stratum[:2]}-{k + 1:04d}"
    data = content.encode("utf-8") if isinstance(content, str) else content
    needle = raw.encode("utf-8")
    count = data.count(needle)
    if count != 1:
        raise SystemExit(f"{item_id} ({template}): {raw!r} occurs {count} times, expected 1")
    offset = data.find(needle)
    if data[offset:offset + len(needle)] != needle:
        raise SystemExit(f"{item_id}: bytes at offset {offset} are not the raw value")
    rel = f"items/{item_id}.{EXT[fmt]}"
    (_out / rel).parent.mkdir(parents=True, exist_ok=True)
    (_out / rel).write_bytes(data)
    _items.append({
        "id": item_id, "stratum": stratum, "split": "heldout" if k % 5 == 0 else "dev",
        "file": rel, "format": fmt, "carrier": carrier, "expected_flag": expected,
        "value": value, "raw": raw, "offset": offset, "length": len(needle),
        "identifiers": ids, "always_flag": always, "health": hl, "sensitive": tags or [],
        "obfuscation": obf, "predicate": predicate, "template": f"{stratum[:2]}.{template}",
    })


# ------------------------------------------------------------------ S1
S1 = [
    ("html", "paragraph", lambda n, h: f"<p>{n} is being treated for {h}.</p>"),
    ("html", "list_item", lambda n, h: f"<ul><li>{n}: {h}</li></ul>"),
    ("html", "table_row", lambda n, h: "<table><tr><th>Patient</th><th>Condition</th></tr>"
                                       f"<tr><td>{n}</td><td>{h}</td></tr></table>"),
    ("html", "note_line", lambda n, h: f'<div class="note">Care note: {n} presents with {h}.</div>'),
    ("html", "blockquote", lambda n, h: f"<blockquote>{n} reports ongoing {h}.</blockquote>"),
    ("html", "definition", lambda n, h: f"<dl><dt>{n}</dt><dd>{h}</dd></dl>"),
    ("txt", "sentence", lambda n, h: f"{n} was seen today for {h}.\n"),
    ("txt", "bullet", lambda n, h: f"Follow-up list:\n- {n} ({h})\n"),
    ("txt", "note", lambda n, h: f"NOTE: {n} - diagnosis {h}\n"),
    ("txt", "memo", lambda n, h: f"Memo to team: please call {n} regarding {h}.\n"),
]


def s1(k: int) -> None:
    fmt, name, fn = S1[k % len(S1)]
    first, last = pick_name()
    n, (dx, _, tags) = f"{first} {last}", health()
    record = fn(n, dx)
    content = page(f"<h1>Care team bulletin</h1><p>{filler()}</p>{record}") if fmt == "html" \
        else f"{filler()}\n{record}"
    add("S1_prose", k, name, fmt, "visible_text", content, n, n, ["names"], hl=dx, tags=tags)


# ------------------------------------------------------------------ S2
def _fhir(p: dict, dx: str, code: str, kind: str, ref: str) -> str:
    patient = {"resourceType": "Patient", "id": "pat-1",
               "name": [{"use": "official", "text": p["name"], "family": p["last"],
                         "given": [p["first"]]}],
               "identifier": [{"system": "urn:clinic:mrn", "value": p["mrn"]}]}
    condition = {"resourceType": "Condition", "id": "cond-1", "subject": {"reference": ref},
                 "code": {"coding": [{"system": "http://hl7.org/fhir/sid/icd-10-cm",
                                      "code": code}], "text": dx}}
    return json.dumps({"resourceType": "Bundle", "type": kind, "entry": [
        {"fullUrl": ref, "resource": patient}, {"resource": condition}]},
        indent=2, ensure_ascii=False) + "\n"


def _hl7(p: dict, dx: str, code: str, msg: str) -> str:
    return "\r".join([
        f"MSH|^~\\&|CLINIC|EXAMPLE|||||{msg}|MSG0001|P|2.5",
        f"PID|1||{p['mrn']}||{p['last']}^{p['first']}",
        f"DG1|1||{code}^{dx}^I10", ""])


def _x12(p: dict, dx: str, code: str, extra: str) -> str:
    return "~\n".join(["ST*837*0001", extra + f"NM1*IL*1*{p['last']}*{p['first']}",
                       f"REF*EA*{p['mrn']}", f"HI*ABK:{code.replace('.', '')}", "SE*5*0001", ""])


def _json(obj: dict) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


# (format, carrier, builder(p, dx, code) -> content, name raw as written)
S2 = [
    ("json_flat", "json", "api_response", lambda p, d, c: _json(
        {"patient_name": p["name"], "mrn": p["mrn"], "diagnosis": d}), lambda p: p["name"]),
    ("json_nested", "json", "api_response", lambda p, d, c: _json(
        {"data": {"patient": {"name": p["name"], "identifiers": {"mrn": p["mrn"]}},
                  "clinical": {"problem": d, "icd10": c}}}), lambda p: p["name"]),
    ("fhir_collection", "json", "api_response",
     lambda p, d, c: _fhir(p, d, c, "collection", "urn:uuid:pat-1"), lambda p: p["name"]),
    ("fhir_searchset", "json", "api_response",
     lambda p, d, c: _fhir(p, d, c, "searchset", "Patient/pat-1"), lambda p: p["name"]),
    ("hl7_adt", "hl7", "data_file", lambda p, d, c: _hl7(p, d, c, "ADT^A01"),
     lambda p: f"{p['last']}^{p['first']}"),
    ("hl7_oru", "hl7", "data_file", lambda p, d, c: _hl7(p, d, c, "ORU^R01"),
     lambda p: f"{p['last']}^{p['first']}"),
    ("csv_name_first", "csv", "data_file", lambda p, d, c:
     f"patient_name,mrn,diagnosis\n{p['name']},{p['mrn']},{d}\n", lambda p: p["name"]),
    ("csv_mrn_first", "csv", "data_file", lambda p, d, c:
     f"record_no,full_name,problem,icd10\n{p['mrn']},{p['name']},{d},{c}\n", lambda p: p["name"]),
    ("x12_837", "x12", "data_file", lambda p, d, c: _x12(p, d, c, ""),
     lambda p: f"{p['last']}*{p['first']}"),
    ("x12_837_payer", "x12", "data_file", lambda p, d, c: _x12(p, d, c, "NM1*PR*2*EXAMPLE PLAN~\n"),
     lambda p: f"{p['last']}*{p['first']}"),
]


def s2(k: int) -> None:
    name, fmt, carrier, build, name_raw = S2[k % len(S2)]
    first, last = pick_name()
    p = {"first": first, "last": last, "name": f"{first} {last}", "mrn": mrn()}
    dx, code, tags = health()
    use_mrn = (k // len(S2)) % 2 == 1  # alternate which of the two identifiers is the target
    raw = p["mrn"] if use_mrn else name_raw(p)
    value = p["mrn"] if use_mrn else p["name"]
    add("S2_structured", k, name, fmt, carrier, build(p, dx, code), raw, value,
        ["names", "mrn"], hl=dx, tags=tags, always=use_mrn)


# ------------------------------------------------------------------ S3
def _storage(n: str, dx: str) -> str:
    area = _rng.choice(["localStorage", "sessionStorage"])
    return ("<script>" + area + f".setItem('last_patient', JSON.stringify({{name: '{n}', "
            f"dx: '{dx}'}}));</script>")


# (carrier, builder(name, dx, title/head...) -> (title, body, raw))
S3 = [
    ("url", lambda n, d: ("Referrals", f'<a href="/portal/results?patient={quote_plus(n)}'
                          f'&amp;dx={quote_plus(d)}">Open result</a>', quote_plus(n))),
    ("page_title", lambda n, d: (f"Lab results for {n} - {d}", "<h1>Your results</h1>", n)),
    ("html_comment", lambda n, d: ("Care team", f"<h1>Care team</h1><!-- internal note: {n}, {d} -->", n)),
    ("css_hidden", lambda n, d: ("Care team", f'<h1>Care team</h1><div style="display:none">{n} - {d}</div>', n)),
    ("aria_hidden", lambda n, d: ("Care team", f'<h1>Care team</h1><span aria-hidden="true">{n} - {d}</span>', n)),
    ("data_attribute", lambda n, d: ("Care team", f'<h1>Care team</h1><div data-patient="{n}" data-dx="{d}">Summary</div>', n)),
    ("json_ld", lambda n, d: ("Care team", '<script type="application/ld+json">'
                              + json.dumps({"@context": "https://schema.org", "@type": "Patient",
                                            "name": n, "diagnosis": d}, ensure_ascii=False)
                              + "</script><h1>Care team</h1>", n)),
    ("web_storage", lambda n, d: ("Preferences", "<h1>Preferences</h1>" + _storage(n, d), n)),
    ("indexeddb", lambda n, d: ("Offline cache", '<script>const store = db.transaction("visits", '
                                f'"readwrite").objectStore("visits"); store.put({{name: "{n}", dx: "{d}"}});'
                                "</script><h1>Offline cache</h1>", n)),
    ("cookie", lambda n, d: ("Welcome back", f'<script>document.cookie = "patient={quote(n, safe="")}; '
                             f'dx={quote_plus(d)}; path=/";</script><h1>Welcome back</h1>',
                             quote(n, safe=""))),
    ("third_party_request", lambda n, d: ("Thank you", f'<h1>Thank you</h1><img src="https://px.tracker.example/p?n={quote_plus(n)}'
                                          f'&amp;dx={quote_plus(d)}" width="1" height="1" alt="">',
                                          quote_plus(n))),
]


def s3(k: int) -> None:
    carrier, build = S3[k % len(S3)]
    first, last = pick_name()
    n, (dx, _, tags) = f"{first} {last}", health()
    title, body, raw = build(n, dx)
    add("S3_web_carriers", k, carrier, "html", carrier, page(body + f"<p>{filler()}</p>", title),
        raw, n, ["names"], hl=dx, tags=tags)


# ------------------------------------------------------------------ S4
def _xlsx(i: str, d: str) -> bytes:
    return docgen.build_xlsx([
        {"name": "Summary", "rows": [["Clinic summary"], [filler()]], "hidden": False},
        {"name": "Data", "rows": [["Name or ID", "Condition"], [i, d]], "hidden": True}])


def _pptx(i: str, d: str) -> bytes:
    return docgen.build_pptx([{"text": "Agenda", "notes": filler()},
                              {"text": "Case review", "notes": f"{i}: {d}"}])


S4 = [
    ("pdf_text", "pdf", "pdf_text_layer", lambda i, d: docgen.build_pdf(
        ["Clinic report", f"Patient: {i}", f"Diagnosis: {d}", filler()], {"Title": "Report"})),
    ("pdf_table", "pdf", "pdf_text_layer", lambda i, d: docgen.build_pdf(
        ["Result summary", "Name or ID | Condition", f"{i} | {d}"], {"Title": "Summary"})),
    ("pdf_info", "pdf", "document_metadata", lambda i, d: docgen.build_pdf(
        ["Clinic report", filler()], {"Author": i, "Subject": d, "Title": "Report"})),
    ("docx_creator", "docx", "document_metadata", lambda i, d: docgen.build_docx(
        [filler()], core={"creator": i, "subject": d, "title": "Notes"})),
    ("docx_subject", "docx", "document_metadata", lambda i, d: docgen.build_docx(
        [filler()], core={"subject": f"{i} - {d}", "lastModifiedBy": "Records Dept"})),
    ("docx_deleted", "docx", "tracked_changes", lambda i, d: docgen.build_docx(
        [filler()], deleted=[f"{i} - {d}"])),
    ("docx_deleted_inserted", "docx", "tracked_changes", lambda i, d: docgen.build_docx(
        [filler()], deleted=[f"Remove: {i} diagnosed with {d}"], inserted=["Entry removed"])),
    ("xlsx_hidden", "xlsx", "hidden_sheet", _xlsx),
    ("pptx_notes", "pptx", "speaker_notes", lambda i, d: docgen.build_pptx(
        [{"text": "Quarterly update", "notes": f"Follow up with {i} about {d}."}])),
    ("pptx_notes_slide2", "pptx", "speaker_notes", _pptx),
    ("exif_description", "jpeg", "exif", lambda i, d: docgen.build_jpeg(
        {"ImageDescription": f"{i} - {d}", "Software": "ClinicCam"})),
    ("exif_artist", "jpeg", "exif", lambda i, d: docgen.build_jpeg(
        {"Artist": i, "ImageDescription": d})),
]


def s4(k: int) -> None:
    name, fmt, carrier, build = S4[k % len(S4)]
    first, last = pick_name(ascii_only=True)  # PDF text is latin-1; keep every byte identical
    dx, _, tags = health()
    use_mrn = (k // len(S4)) % 4 == 3
    ident = mrn() if use_mrn else f"{first} {last}"
    add("S4_documents", k, name, fmt, carrier, build(ident, dx), ident, ident,
        ["mrn" if use_mrn else "names"], hl=dx, tags=tags, always=use_mrn)


# ------------------------------------------------------------------ S5
S5_COL = {"ssn": "ssn", "mrn": "mrn", "plan_id": "member_id"}
S5 = [
    ("log_lookup", "log", "log", False, lambda v, c: f'level=INFO msg="eligibility check" {c}={v}\n'),
    ("log_warning", "log", "log", False, lambda v, c: f"WARN duplicate record {v} skipped\n"),
    ("csv_export", "csv", "data_file", False, lambda v, c: f"{c},status\n{v},active\n"),
    ("csv_rows", "csv", "data_file", False, lambda v, c: f"row,{c}\n1,{v}\n"),
    ("url_query", "html", "url", True, lambda v, c: page(f'<a href="/lookup?{c}={v}">Look up</a>')),
    ("json_body", "json", "api_response", False, lambda v, c: _json({c: v, "status": "active"})),
    ("html_text", "html", "visible_text", False, lambda v, c: page(f"<p>Reference: {v}</p>")),
    ("error_page", "html", "error_surface", False,
     lambda v, c: page(f"<h1>Error</h1><pre>ValueError: no match for {v}</pre>")),
]


def s5(k: int) -> None:
    name, fmt, carrier, plain, build = S5[k % len(S5)]
    kind = ["ssn", "mrn", "plan_id"][(k // len(S5)) % 3]
    value = always_id(kind, plain)
    add("S5_always_flag", k, name, fmt, carrier, build(value, S5_COL[kind]), value, value,
        [kind], always=True)


# ------------------------------------------------------------------ S6
def _insert_inside(s: str, mark: str) -> str:
    pos = _rng.randint(1, len(s) - 1)
    while s[pos - 1] == " " or s[pos] == " ":
        pos = _rng.randint(1, len(s) - 1)
    return s[:pos] + mark + s[pos:]


def _entities(s: str) -> str:
    keep = [c.isalnum() and _rng.random() < 0.4 for c in s]
    keep[next(i for i, c in enumerate(s) if c.isalnum())] = True
    return "".join(f"&#{ord(c)};" if on else c for c, on in zip(s, keep))


def _homoglyph(s: str) -> str:
    out = "".join(HOMOGLYPH.get(c, c) if _rng.random() < 0.6 else c for c in s)
    if out == s:  # force at least one swap
        i = next(i for i, c in enumerate(s) if c in HOMOGLYPH)
        out = s[:i] + HOMOGLYPH[s[i]] + s[i + 1:]
    return out


def _spelled(v: str) -> str:
    return " - ".join(" ".join(DIGIT_WORDS[int(c)] for c in part) for part in v.split("-"))


def s6(k: int) -> None:
    tech, j = TECHNIQUES[k // 20], k % 20
    first, last = pick_name()
    while tech == "homoglyph" and not any(c in HOMOGLYPH for c in first + last):
        first, last = pick_name()
    n, (dx, _, tags) = f"{first} {last}", health()
    kind = ["ssn", "mrn", "plan_id"][(j // 2) % 3]
    by_name = {"homoglyph": True, "base64": True, "split_nodes": True, "spelled_out": False,
               "digit_substitution": False}.get(tech, j % 2 == 0)
    if tech == "spelled_out":
        kind = "ssn"
    elif tech == "digit_substitution":
        kind = "ssn" if j % 2 == 0 else "mrn"
    value = n if by_name else always_id(kind)
    while tech == "digit_substitution" and not re.search("[01]", value):
        value = always_id(kind)
    carrier, template = "visible_text", tech
    if tech == "zero_width":
        raw = _insert_inside(value, "​")
    elif tech == "homoglyph":
        raw = _homoglyph(value)
    elif tech == "html_entities":
        raw = _entities(value)
    elif tech == "rtl":
        raw = "‮" + value + "‬"
    elif tech == "spelled_out":
        raw = _spelled(value)
    elif tech == "digit_substitution":
        raw = value.replace("0", "O").replace("1", "l")
    elif tech == "split_nodes":
        cut = _rng.randint(1, len(n) - 1)
        raw = n[:cut] + '</span><span class="n">' + n[cut:]
    else:  # base64: the whole record is encoded, and the encoded text is what we locate
        record = json.dumps({"name": n, "diagnosis": dx}, ensure_ascii=False)
        raw = base64.b64encode(record.encode("utf-8")).decode("ascii")
    if tech == "base64":
        carrier = "data_attribute" if j % 2 == 0 else "web_storage"
        body = f'<div data-cache="{raw}">Cached view</div>' if j % 2 == 0 else \
            f'<script>localStorage.setItem("cache", "{raw}");</script>'
    elif tech == "split_nodes":
        body = f'<p><span class="n">{raw}</span> is being treated for {dx}.</p>'
    elif by_name:
        body = f"<p>{raw} is being treated for {dx}.</p>"
    else:
        body = f"<p>Reference: {raw}</p>"
    add("S6_obfuscated", k, template, "html", carrier, page(f"<h1>Notes</h1>{body}"), raw, value,
        ["names"] if by_name else [kind], hl=dx if by_name else None,
        tags=tags if by_name else [], obf=tech, always=not by_name)


# ------------------------------------------------------------------ N1
def n1(k: int) -> None:
    first, last = pick_name()
    n, spec, npi = f"{first} {last}", _rng.choice(SPECIALTIES), luhn_npi()
    raw = f"Dr. {n}, {_rng.choice(['MD', 'DO'])}"
    ld = json.dumps({"@context": "https://schema.org", "@type": "Physician",
                     "honorificPrefix": "Dr.", "name": n, "medicalSpecialty": spec,
                     "identifier": npi}, ensure_ascii=False)
    shapes = [
        ("profile_ld", "html", "visible_text", raw, page(
            f"<h1>{raw}</h1><p>{spec}</p><p>NPI: {npi}</p>"
            f'<script type="application/ld+json">{ld}</script>', "Our providers")),
        ("directory_item", "html", "visible_text", raw, page(
            f"<ul><li>{raw} - {spec} - NPI {npi}</li></ul>", "Provider directory")),
        ("staff_table", "html", "visible_text", raw, page(
            f"<table><tr><td>{raw}</td><td>{spec}</td><td>{npi}</td></tr></table>", "Our team")),
        ("bio", "html", "visible_text", raw, page(
            f"<p>{raw} is a {spec} specialist at our clinic (NPI {npi}).</p>", "Meet the team")),
        ("providers_api", "json", "api_response", raw, _json(
            {"providers": [{"name": raw, "specialty": spec, "npi": npi}]})),
        ("staff_txt", "txt", "visible_text", raw, f"Staff directory\n{raw}, {spec} (NPI {npi})\n"),
        ("ld_only", "html", "json_ld", n, page(
            f'<h1>Provider profile</h1><script type="application/ld+json">{ld}</script>'
            f"<p>{filler()}</p>", "Provider profile")),
    ]
    name, fmt, carrier, rraw, content = shapes[k % len(shapes)]
    add("N1_provider_staff_page", k, name, fmt, carrier, content, rraw, n, ["names"],
        expected=False, predicate="provider_staff_page")


# ------------------------------------------------------------------ N2 / N3
def n2(k: int) -> None:
    dx, _, tags = health()
    author = " ".join(pick_name())
    shapes = [
        ("article", "html", dx, dx, page(
            f"<h1>Health guide</h1><p>Learn about {dx}: common signs, screening and treatment "
            f"options.</p><p>{filler()}</p>")),
        ("faq", "html", dx, dx, page(
            f"<h1>Questions answered</h1><dl><dt>What is {dx}?</dt><dd>It is a condition your "
            "clinician can explain and manage with you.</dd></dl>")),
        ("txt_article", "txt", dx, dx,
         f"Health guide\nWhat to know about {dx}: signs, screening, treatment options.\n"),
        ("byline_html", "html", author, author, page(
            f'<h1>Health guide</h1><p class="byline">By {author}, MPH</p>'
            f"<p>An overview of {dx} and how it is treated.</p>")),
        ("byline_txt", "txt", author, author,
         f"Health guide\nWritten by {author}\nAn overview of {dx} and how it is treated.\n"),
    ]
    name, fmt, raw, value, content = shapes[k % len(shapes)]
    add("N2_public_health_article", k, name, fmt, "visible_text", content, raw, value,
        ["names"] if raw == author else [], hl=dx, tags=tags, expected=False,
        predicate="public_health_article")


def n3(k: int) -> None:
    dx, _, tags = health()
    total = _rng.randint(200, 5000)
    count = _rng.randint(11, min(total // 2, 900))
    shapes = [
        ("sentence", "html", "visible_text", page(
            f"<h1>Annual outcomes</h1><p>Of {total} adults screened, {count} had {dx}.</p>")),
        ("table", "html", "visible_text", page(
            "<table><tr><th>Condition</th><th>Adults</th></tr>"
            f"<tr><td>{dx}</td><td>{count}</td></tr></table>")),
        ("txt", "txt", "visible_text", f"Group summary: {count} of {total} members have {dx}.\n"),
        ("csv", "csv", "data_file", f"condition,adults,total\n{dx},{count},{total}\n"),
        ("json", "json", "api_response", _json(
            {"group": "adults", "condition": dx, "count": count, "total": total})),
    ]
    name, fmt, carrier, content = shapes[k % len(shapes)]
    add("N3_group_statistics", k, name, fmt, carrier, content, dx, dx, [], hl=dx, tags=tags,
        expected=False, predicate="group_statistics")


# ------------------------------------------------------------------ N4 / N5 / N6
def n4(k: int) -> None:
    kind = ["ssn", "phone", "email", "ip"][k % 4]
    label = {"ssn": "SSN", "phone": "Phone", "email": "Email", "ip": "IP address"}[kind]
    v = reserved(kind)
    shapes = [
        ("form", "html", "visible_text", page(
            f'<h1>Sample intake form</h1><p>Fictional example data.</p><label>{label}</label>'
            f'<input type="text" value="{v}">')),
        ("api_example", "json", "api_response", _json({"example": {kind: v}, "note": "documentation"})),
        ("doc_text", "txt", "visible_text", f"Example {label} for documentation only: {v}\n"),
    ]
    name, fmt, carrier, content = shapes[(k // 4) % len(shapes)]
    add("N4_reserved_synthetic_value", k, f"{name}_{kind}", fmt, carrier, content, v, v, [kind],
        expected=False, predicate="reserved_synthetic_value")


def n5(k: int) -> None:
    org = f"{_rng.choice(ORG_A)} {_rng.choice(ORG_B)}"
    ph, slug = phone(), org.lower().replace(" ", "")
    address = f"{_fake.street_address()}, {_fake.city()}, {_fake.state_abbr()} {_fake.postcode()}"
    ld = json.dumps({"@context": "https://schema.org", "@type": "Organization", "name": org,
                     "telephone": ph, "email": f"info@{slug}.example"}, ensure_ascii=False)
    shapes = [
        ("contact_page", "html", "visible_text", page(
            f"<h1>Contact {org}</h1><p>Main line: {ph}</p><p>{address}</p>"
            f"<p>info@{slug}.example</p>", "Contact us")),
        ("footer", "html", "visible_text", page(
            f"<p>{filler()}</p><footer>{org} | {address} | Tel {ph} | info@{slug}.example</footer>")),
        ("org_ld", "html", "json_ld", page(
            f'<h1>{org}</h1><script type="application/ld+json">{ld}</script>')),
        ("signature", "txt", "visible_text", f"{org}\n{address}\nMain: {ph}\ninfo@{slug}.example\n"),
        ("address_block", "html", "visible_text", page(
            f"<address><strong>{org}</strong><br>{address}<br>Phone: {ph}</address>")),
    ]
    name, fmt, carrier, content = shapes[k % len(shapes)]
    add("N5_company_contact", k, name, fmt, carrier, content, ph, ph, ["phone"],
        expected=False, predicate="company_contact")


def n6(k: int) -> None:
    system, pool = [("ICD-10", ICD), ("CPT", CPT), ("LOINC", LOINC)][k % 3]
    rows = _rng.sample(pool, 5)
    code = rows[0][0]
    table = "".join(f"<tr><td>{c}</td><td>{d}</td></tr>" for c, d in rows)
    shapes = [
        ("table", "html", "visible_text", page(
            f"<h1>{system} reference</h1><table><tr><th>Code</th><th>Description</th></tr>"
            f"{table}</table>")),
        ("list", "txt", "visible_text", f"{system} codes\n" + "".join(f"{c}  {d}\n" for c, d in rows)),
        ("csv", "csv", "data_file", "code,description\n" + "".join(f"{c},{d}\n" for c, d in rows)),
        ("json", "json", "api_response", _json({"system": system,
                                                "codes": [{"code": c, "display": d} for c, d in rows]})),
    ]
    name, fmt, carrier, content = shapes[(k // 3) % len(shapes)]
    add("N6_code_reference", k, f"{name}_{system.lower().replace('-', '')}", fmt, carrier, content,
        code, code, [], expected=False, predicate="code_reference")


# ------------------------------------------------------------------ N7 / N8
def n7(k: int) -> None:
    n = " ".join(pick_name())
    role = _rng.choice(["Chief Operating Officer", "Volunteer coordinator", "Event chair",
                        "Board treasurer", "Program director"])
    shapes = [
        ("speaker", "html", "visible_text", page(
            f"<h1>Annual meeting</h1><p>Keynote speaker: {n}, {role}.</p>")),
        ("newsletter", "txt", "visible_text",
         f"Community newsletter\nVolunteer of the month: {n}, {role}. {filler()}\n"),
        ("committee", "html", "visible_text", page(f"<ul><li>{n} - {role}</li></ul>")),
        ("speakers_api", "json", "api_response", _json({"speakers": [{"name": n, "role": role}]})),
        ("welcome", "html", "visible_text", page(
            f"<p>Please welcome {n}, our new {role}.</p><p>{filler()}</p>")),
    ]
    name, fmt, carrier, content = shapes[k % len(shapes)]
    add("N7_identity_without_health", k, name, fmt, carrier, content, n, n, ["names"],
        expected=False, predicate="identity_without_health")


def n8(k: int) -> None:
    n, (dx, _, tags), mark = " ".join(pick_name()), health(), _rng.choice(CONSENT)
    shapes = [
        ("blockquote", "html", "visible_text", page(
            f'<blockquote>"I live with {dx}. The support group helped."<cite>{n}</cite></blockquote>'
            f"<p>{mark}.</p>")),
        ("txt", "txt", "visible_text", f"Testimonial ({mark}): {n} - {dx}.\n"),
        ("json", "json", "api_response", _json(
            {"testimonial": {"name": n, "condition": dx, "consent_note": mark}})),
        ("figure", "html", "visible_text", page(
            f"<figure><figcaption>{n}, living with {dx}</figcaption></figure><small>{mark}</small>")),
        ("table", "html", "visible_text", page(
            f"<table><tr><td>{n}</td><td>{dx}</td><td>{mark}</td></tr></table>")),
    ]
    name, fmt, carrier, content = shapes[k % len(shapes)]
    add("N8_consented_testimonial", k, name, fmt, carrier, content, n, n, ["names"], hl=dx,
        tags=tags, expected=False, predicate="consented_testimonial")


STRATA = [("S1_prose", 160, s1), ("S2_structured", 160, s2), ("S3_web_carriers", 160, s3),
          ("S4_documents", 160, s4), ("S5_always_flag", 160, s5), ("S6_obfuscated", 160, s6),
          ("N1_provider_staff_page", 90, n1), ("N2_public_health_article", 90, n2),
          ("N3_group_statistics", 90, n3), ("N4_reserved_synthetic_value", 90, n4),
          ("N5_company_contact", 90, n5), ("N6_code_reference", 90, n6),
          ("N7_identity_without_health", 90, n7), ("N8_consented_testimonial", 90, n8)]


def build(out_root: Path, key_path: Path) -> dict:
    """Write every item under out_root and the answer key at key_path; return the key."""
    global _rng, _fake, _out, _items
    _rng, _out, _items = random.Random(SEED), out_root, []
    Faker.seed(SEED)
    _fake = Faker("en_US")
    _fake.seed_instance(SEED)
    for _, count, make in STRATA:
        for k in range(count):
            make(k)
    counts = {s: sum(1 for i in _items if i["stratum"] == s) for s, _, _ in STRATA}
    positives = sum(v for s, v in counts.items() if s.startswith("S"))
    counts.update(positives=positives, negatives=len(_items) - positives, total=len(_items))
    key = {"version": 1, "generator": "fixtures/build_corpus.py", "seed": SEED,
           "context": "public-web", "counts": counts, "items": _items}
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(json.dumps(key, indent=2, sort_keys=True) + "\n", encoding="utf-8",
                        newline="\n")
    return key


def main() -> int:
    out, key_path = ROOT / "fixtures" / "corpus", ROOT / "eval" / "keys" / "corpus_key.json"
    if out.exists():
        shutil.rmtree(out)
    key = build(out, key_path)
    for stratum, count in key["counts"].items():
        print(f"  {stratum:30s} {count}")
    print(f"  key sha256 : {hashlib.sha256(key_path.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
