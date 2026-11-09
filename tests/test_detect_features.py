"""One test per detector feature: the positive case and a control that must stay quiet."""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phi_scan.collect import collect  # noqa: E402
from phi_scan.detect import detect, units_for  # noqa: E402


def scan(tmp_path, monkeypatch, files: dict[str, str], context="covered-entity"):
    monkeypatch.setenv("PHI_EVIDENCE_KEYS", str(tmp_path / "keys"))
    source = tmp_path / "src"
    for name, content in files.items():
        (source / name).parent.mkdir(parents=True, exist_ok=True)
        (source / name).write_text(content, encoding="utf-8")
    out = tmp_path / "out"
    collect(source, out)
    return detect(out / "index.jsonl", out / "vault", context=context)


def sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def tracker(value: str) -> str:
    return f'<img src="https://t.tracker.io/p?h={sha(value)}">'


def test_hashed_identifier_in_third_party_request(tmp_path, monkeypatch):
    page = ("<html><body><p>Reach us at Jane.Roe@Mail.org or 218-555-0147.</p>"
            + tracker("jane.roe@mail.org") + tracker("12185550147") + "</body></html>")
    found = scan(tmp_path, monkeypatch, {"a.html": page}, "public-web")
    hashed = [f for f in found if f["extraction"] == "hashed_identifier"]
    assert sorted(f["identifiers"][0] for f in hashed) == ["email", "phone"]
    assert all(f["carrier"] == "third_party" and f["level"] == "critical" for f in hashed)
    assert all(len(f["value_hashes"]) == 1 for f in hashed)
    assert "jane.roe" not in json.dumps(found).lower()

    control = ("<html><body><p>Reach us at Jane.Roe@Mail.org.</p>"
               + tracker("someone.else@elsewhere.org") + "</body></html>")
    found = scan(tmp_path / "c", monkeypatch, {"a.html": control}, "public-web")
    assert not [f for f in found if f["extraction"] == "hashed_identifier"]


def test_person_labels_link_across_findings(tmp_path, monkeypatch):
    files = {
        "a.txt": "Patient: John Smith, MRN 4455667, diagnosis diabetes mellitus.",
        "b.txt": "Referral for J. Smith with diabetes mellitus, follow up in March.",
        "c.txt": "Patient: Alice Brown, MRN 7788991, diagnosis hypertension.",
    }
    by_path = {f["path"]: f["person"] for f in scan(tmp_path, monkeypatch, files)}
    assert by_path["a.txt"] == by_path["b.txt"]
    assert by_path["c.txt"] != by_path["a.txt"]
    assert all(label.startswith("p") for label in by_path.values())


def test_format_induction_learns_record_number_shape(tmp_path, monkeypatch):
    labelled = {"a.txt": "MRN: ABC123456789 admitted with asthma.",
                "b.txt": "Patient id: DEF987654321 discharged.",
                "c.txt": "Note about XYZ555444333 follows the asthma plan."}
    found = scan(tmp_path, monkeypatch, labelled)
    assert any("mrn" in f["identifiers"] for f in found if f["path"] == "c.txt")

    once = {k: v for k, v in labelled.items() if k != "b.txt"}
    found = scan(tmp_path / "c", monkeypatch, once)
    assert not any("mrn" in f["identifiers"] for f in found if f["path"] == "c.txt")


def test_quasi_identifiers(tmp_path, monkeypatch):
    record = "Visit summary\nGender: Female\nDOB: 1984-03-12\nResidence: Duluth, MN 55803\n"
    found = scan(tmp_path, monkeypatch, {"a.txt": record})
    quasi = [f for f in found if f["identifiers"] == ["quasi_identifiers"]]
    assert len(quasi) == 1
    assert quasi[0]["level"] == "review" and quasi[0]["extraction"] == "quasi_identifier"
    assert quasi[0]["value_mask"] == "*" * 1 + "5803"

    without_sex = record.replace("Gender: Female\n", "")
    found = scan(tmp_path / "c", monkeypatch, {"a.txt": without_sex})
    assert not [f for f in found if f["identifiers"] == ["quasi_identifiers"]]


def test_json_record_linker():
    linked = [{"id": "p1", "name": "Maria Lopez"},
              {"id": "v1", "patient_id": "p1", "diagnosis": "diabetes"}]
    units = [u for _, u in units_for("api_response", "v.json", json.dumps(linked), "raw")]
    assert any("Maria Lopez" in u and "diabetes" in u for u in units)

    dangling = [linked[0], {"id": "v1", "patient_id": "p9", "diagnosis": "diabetes"}]
    units = [u for _, u in units_for("api_response", "v.json", json.dumps(dangling), "raw")]
    assert not any("Maria Lopez" in u and "diabetes" in u for u in units)
