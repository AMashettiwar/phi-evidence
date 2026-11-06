"""False alarms from the first real application scanned (2026-11-03).

A Vue single-page app with Vuetify styles: 12 findings, all wrong. Each test
below rebuilds one cause from scratch (no code from that app is copied here)
and pairs it with a planted leak in the same place, so a fix that only went
quiet would fail.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phi_scan.collect import collect  # noqa: E402
from phi_scan.detect import (detect, digest, identifiers, name_shaped,  # noqa: E402
                             organisation_names, placeholder_number)
from phi_scan.vault import Vault  # noqa: E402

LEAK = "Rafael Ibarra, MRN 448812, started chemotherapy for breast cancer"


def scan(tmp_path, monkeypatch, files: dict[str, str]) -> tuple[list[dict], Vault, list[dict]]:
    monkeypatch.setenv("PHI_EVIDENCE_KEYS", str(tmp_path / "keys"))
    source = tmp_path / "src"
    for name, content in files.items():
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8"))
    out = tmp_path / "out"
    collect(source, out)
    rows = [json.loads(line) for line in (out / "index.jsonl").read_text(encoding="utf-8").splitlines()]
    return detect(out / "index.jsonl", out / "vault", (), context="public-web"), Vault(out / "vault"), rows


# Styling a framework ships: a font stack and colour classes whose hex codes
# are six digits, which beside a "name" read as a record number.
FONTS = "font-family: Inter, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;"
COLOURS = "".join(f".bg-indigo-darken-{n}{{background-color:#{code}!important}}"
                  for n, code in enumerate(("283593", "303f9f", "1a237e", "3949ab"), 1))


def test_style_block_reads_only_displayed_text(tmp_path, monkeypatch):
    page = f"<html><head><style>body {{ {FONTS} }} {COLOURS}</style></head><body><p>Welcome</p></body></html>"
    assert scan(tmp_path, monkeypatch, {"index.html": page})[0] == []
    shown = page.replace("</style>", f'.who::after{{content:"{LEAK}"}}</style>')
    assert scan(tmp_path / "leak", monkeypatch, {"index.html": shown})[0]


def test_print_stylesheet_reads_only_displayed_text(tmp_path, monkeypatch):
    css = f"body{{{FONTS}}}{COLOURS}@media print{{.receipt{{color:#000}}}}"
    assert scan(tmp_path, monkeypatch, {"assets/index-0e83666a.css": css})[0] == []
    shown = css.replace(".receipt{color:#000}", f'.receipt::after{{content:"{LEAK}"}}')
    assert scan(tmp_path / "leak", monkeypatch, {"assets/print.css": shown})[0]


def test_svg_attributes_are_not_text(tmp_path, monkeypatch):
    # The drawing attribute "stroke" read as the disease, the font as a person.
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 210 64"><title>Northbridge</title>'
           '<circle cx="28" cy="32" r="21" fill="none" stroke="#0F7C93" stroke-width="3.4" />'
           f'<text x="60" y="41" font-family="Inter, \'Segoe UI\', Roboto, Arial">Northbridge</text></svg>')
    assert scan(tmp_path, monkeypatch, {"branding/logo.svg": svg})[0] == []
    shown = svg.replace(">Northbridge</text>", f">{LEAK}</text>")
    assert scan(tmp_path / "leak", monkeypatch, {"branding/logo.svg": shown})[0]


def test_department_names_are_not_people(tmp_path, monkeypatch):
    meta = ('<html><head><meta name="description" content="Northbridge University '
            'Digital Pathology image catalogue and viewer"></head><body></body></html>')
    assert scan(tmp_path, monkeypatch, {"index.html": meta})[0] == []
    assert identifiers("Department of Radiology and Cardiac Sonography")["keys"] == []
    # A first name before a product word is a product, as a page title.
    title = "<html><head><title>Harper Digital Pathology</title></head><body></body></html>"
    assert scan(tmp_path / "title", monkeypatch, {"index.html": title})[0] == []
    # A person before a department word is still a person.
    assert "names" in identifiers("Rafael Ibarra Oncology Report")["keys"]


def test_small_minified_chunk_is_code(tmp_path, monkeypatch):
    # A code-split chunk: one line, a few thousand characters, title-case UI
    # strings, a placeholder email and a six-zero verification-code hint.
    parts = ['import{a as e,b as t}from"./index-4c7a6379.js";',
             'const n={class:"auth-shell"},o={label:"Verification code",placeholder:"000000",maxlength:"6"};',
             'const r={title:"Digital Pathology",sub:"Image Catalogue",email:"name@northbridge.edu"};']
    parts += [f"function f{i}(a,s){{return a.value?s(\"Sign In\",{{class:\"v-btn-{i}\"}}):null}};" for i in range(60)]
    chunk = "".join(parts) + "\n"
    found, _, rows = scan(tmp_path, monkeypatch, {"assets/LoginView-1c1031d2.js": chunk})
    assert all(r["extraction"].startswith("minified") for r in rows if r["carrier"] == "js_bundle")
    assert found == []


def test_repeated_digit_placeholder_is_not_a_record_number():
    assert "mrn" not in identifiers("Rafael Ibarra: enter the code 000000")["keys"]
    assert "mrn" in identifiers("Rafael Ibarra 4488127")["keys"]


# Rules from the realistic hospital site (fixtures/build_realsite.py,
# tools/check_realsite.py). Each pairs what must stay quiet with what must not.

def test_placeholders_are_not_people_or_records():
    assert placeholder_number("123456789") and placeholder_number("987654")
    assert not placeholder_number("4471829")
    card = "Sample card. Member name: JOHN Q SAMPLE. Member ID: XYZ123456789. Group number: 000123."
    assert identifiers(card)["keys"] == []
    assert "mrn" in identifiers("Member name: Ellen Burke. Member ID: 4471829.")["keys"]


def test_names_must_look_like_names():
    assert not name_shaped('ia=!("undefined"===typeof window')
    assert name_shaped("Mary-Jane O'Neil") and name_shaped("Maria de la Cruz") and name_shaped("José García")


def test_lists_states_and_labels_are_not_names():
    for text in ("Hospitals, Doctors and Care in Riverton, Ohio", "Member ID and Rx BIN", "FHIR API docs"):
        assert identifiers(text)["names"] == [], text
    assert identifiers("IBARRA, RAFAEL - pathology report")["names"]


def test_organisation_name_repeated_on_the_page():
    page = "Mercy Valley Health | Hospitals\nMercy Valley opens a cancer center\n© Mercy Valley Health"
    assert "Mercy Valley" in organisation_names(page)
    # Once is not enough: a leaked record names its patient once.
    assert "Helen Marsh" not in organisation_names("Helen Marsh Health History: chemotherapy")


def test_schema_org_things_are_not_people():
    event = ('{"@type":"Event","name":"Diabetes support group",'
             '"location":{"@type":"Place","name":"Community Room B"}}')
    assert identifiers(event)["names"] == []
    patient = '{"@type":"Patient","name":"Rosa Delgado","healthCondition":{"name":"breast cancer"}}'
    assert identifiers(patient)["names"] == ["Rosa Delgado"]


def test_code_names_need_a_record_beside_them():
    comment = "// Core Schema: Parses YAML. const MAX = 4194304; // 2023-02-29"
    assert identifiers(comment, code=True)["keys"] == ["dates"]
    hardcoded = "const DEBUG = 'Ana Ruiz|MRN-880137|E11.9';"
    assert {"names", "mrn"} <= set(identifiers(hardcoded, code=True)["keys"])


# Rules from the first public real site: the HAPI FHIR test server (2026-11-05).

def test_acronyms_and_code_identifiers_are_not_names():
    for name in ("HAPI FHIR", "Swagger UI", "Server Base URL", "CatalogEntry Index", "OpenAPI Docs"):
        assert not name_shaped(name), name
    for name in ("Ronald McDonald", "LaToya Jackson", "Leonardo DiCaprio", "Mary-Jane O'Neil", "SMITH JOHN"):
        assert name_shaped(name), name


def test_interface_wording_alone_is_not_a_person(tmp_path, monkeypatch):
    page = ("<html><head><title>Server Home</title></head><body>"
            "<!-- ** Server Actions (no resource selected) ** --><p>Get Tags</p>"
            "<script>// Begin Swagger UI call region\nconst counts = {Observation: 112641};</script>"
            "</body></html>")
    assert scan(tmp_path, monkeypatch, {"index.html": page})[0] == []
    # A name with a date beside it in a hidden place is still a record.
    hidden = page.replace("<p>Get Tags</p>", '<span style="position:absolute;left:-9999px">'
                                             "Rosa Delgado 1958-07-14</span>")
    assert scan(tmp_path / "leak", monkeypatch, {"index.html": hidden})[0]


def test_a_number_far_from_a_name_is_not_their_record():
    statement = ('{"contact": [{"name": "Dr. Lena Fischer"}], ' + '"x": 1, ' * 120
                 + '"resource": [{"type": "Observation", "count": 112641}]}')
    assert "mrn" not in identifiers(statement)["keys"]
    assert "mrn" in identifiers("Dr. Lena Fischer saw the patient, chart 4471829.")["keys"]


def test_counts_beside_interface_words_are_not_record_numbers():
    assert "mrn" not in identifiers("Server Actions | Observation 112641 | Patient 29131")["keys"]
    assert "mrn" in identifiers("Patient: Rosa Delgado 4471829")["keys"]


def test_health_must_be_near_a_weak_name_in_a_long_block():
    menu = "Server Home | " + " | ".join(f"Resource{i} {i}" for i in range(60)) + " | breast cancer screening"
    assert len(menu) > 300
    ids = identifiers(menu)
    assert ids["names"] and not ids["person"]
    story = "Emeka Delgado was treated for breast cancer at the oncology clinic last spring."
    assert identifiers(story)["names"]


def test_labelled_name_in_a_script_is_backed():
    ids = identifiers("window.__lastSearch = {name: 'Rafael Ibarra', dx: 'breast cancer'};")
    assert ids["person"]


def test_tech_acronyms_are_not_chemicals():
    from phi_scan.clinical import health
    assert not health("Server | HFQL / SQL | Resources")[0]
    assert health("started HCTZ for hypertension")[0]


def test_labelled_and_model_backed_names_still_count(tmp_path, monkeypatch):
    """The weak-name rule first cost 16 corpus leaks (G5): the attribute's own
    name labels its value, and a name the model recognises is never weak."""
    labelled = ('<html><body><div data-patient="Russell Foster" data-dx="prenatal care">'
                'Summary</div></body></html>')
    assert scan(tmp_path, monkeypatch, {"a.html": labelled})[0]
    hidden = ('<html><body><span aria-hidden="true">Zachary Kline - chronic obstructive '
              'pulmonary disease</span></body></html>')
    assert scan(tmp_path / "b", monkeypatch, {"b.html": hidden})[0]
    interface = '<html><body><button data-tooltip="Server Actions">Go</button></body></html>'
    assert scan(tmp_path / "c", monkeypatch, {"c.html": interface})[0] == []


def test_patients_in_one_bundle_stay_separate_people(tmp_path, monkeypatch):
    """HAPI's Patient search returned 20 patients in one bundle; the whole-
    bundle finding carried all their record numbers and linked them into one."""
    people = [("Rosa", "Delgado", "4471829"), ("Helen", "Marsh", "8823140"),
              ("Gary", "Whitfield", "5512093"), ("Dorothy", "Sims", "6619027")]
    bundle = {"resourceType": "Bundle", "type": "searchset", "entry": [
        {"resource": {"resourceType": "Patient", "name": [{"family": last, "given": [first]}],
                      "identifier": [{"type": {"text": "MRN"}, "value": mrn}],
                      "birthDate": "1960-01-0" + str(i + 1)}}
        for i, (first, last, mrn) in enumerate(people)]}
    found, _, _ = scan(tmp_path, monkeypatch, {"patients.json": json.dumps(bundle)})
    assert len(found) >= len(people)
    assert len({f["person"] for f in found}) >= len(people)


def test_staff_named_on_the_page_but_never_a_patient(tmp_path, monkeypatch):
    staff = ("<html><head><title>New cancer center</title></head><body><p>&ldquo;Care close to home "
             "matters,&rdquo; said Marcus Webb, president and CEO. The center treats breast and lung "
             "cancer.</p><p>Led by Dr. Lena Fischer.</p></body></html>")
    assert scan(tmp_path, monkeypatch, {"news/center.html": staff})[0] == []
    patient = staff.replace("</body>", "<p>Helen Marsh began chemotherapy for lung cancer "
                                       "with Dr. Lena Fischer.</p></body>")
    assert scan(tmp_path / "leak", monkeypatch, {"news/center.html": patient})[0]


def test_evidence_points_at_the_value_after_non_ascii_text(tmp_path, monkeypatch):
    # Before the fix, a character position was used as a byte position: each
    # "·" or "é" before the value moved the evidence one byte too early.
    script = f'// Café · Résumé — notes\nconst note = "{LEAK}";\n'
    found, vault, _ = scan(tmp_path, monkeypatch, {"notes.js": script})
    assert found
    for finding in found:
        raw = vault.get(finding["doc"])[finding["offset"]:finding["offset"] + finding["length"]]
        # digest() is keyed by the scan that just ran, so this is the same token.
        assert digest(raw.decode("utf-8")) == finding["value_hash"], raw
