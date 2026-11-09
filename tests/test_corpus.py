import hashlib
import io
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path

import pytest
from pypdf import PdfReader

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fixtures"))
import build_corpus  # noqa: E402

SSN = re.compile(r"^\d{3}-\d{2}-\d{4}$")


def _valid_ssn(v: str) -> bool:
    area, group, serial = v.split("-")
    return (1 <= int(area) <= 899 and area != "666" and group != "00" and serial != "0000"
            and not (area == "987" and group == "65" and 4320 <= int(serial) <= 4329))


def _reserved_ssn(v: str) -> bool:
    area, group, serial = v.split("-")
    return (area in ("000", "666") or group == "00" or serial == "0000"
            or (area == "987" and group == "65" and 4320 <= int(serial) <= 4329))


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    root = tmp_path_factory.mktemp("corpus")
    key = build_corpus.build(root / "a", root / "a_key.json")
    return root, key


def _positive(i):
    return i["stratum"].startswith("S")


def test_counts_and_ids(built):
    _, key = built
    items = key["items"]
    by = Counter(i["stratum"] for i in items)
    assert [by[s] for s in by if s.startswith("S")] == [160] * 6
    assert [by[s] for s in by if s.startswith("N")] == [90] * 8
    assert sum(1 for i in items if _positive(i)) == 960
    assert sum(1 for i in items if not _positive(i)) == 720
    assert 720 / len(items) >= 0.4
    assert len({i["id"] for i in items}) == len(items)
    assert all(i["expected_flag"] == _positive(i) for i in items)


def test_offset_and_raw_invariant(built):
    root, key = built
    for i in key["items"]:
        data = (root / "a" / i["file"]).read_bytes()
        raw = i["raw"].encode("utf-8")
        assert i["length"] == len(raw)
        assert data[i["offset"]:i["offset"] + i["length"]] == raw
        assert data.count(raw) == 1


def test_heldout_is_a_fifth_of_every_stratum(built):
    _, key = built
    for stratum in {i["stratum"] for i in key["items"]}:
        items = [i for i in key["items"] if i["stratum"] == stratum]
        held = sum(i["split"] == "heldout" for i in items)
        assert abs(held - len(items) / 5) <= 1


def test_two_builds_are_identical(built, tmp_path):
    root, key = built
    build_corpus.build(tmp_path / "b", tmp_path / "b_key.json")
    assert hashlib.sha256((root / "a_key.json").read_bytes()).digest() == \
        hashlib.sha256((tmp_path / "b_key.json").read_bytes()).digest()
    for i in key["items"][::37]:
        assert (root / "a" / i["file"]).read_bytes() == (tmp_path / "b" / i["file"]).read_bytes()


def test_carriers_are_allowed(built):
    _, key = built
    assert {i["carrier"] for i in key["items"]} <= build_corpus.CARRIERS


def test_s5_is_identifier_alone(built):
    _, key = built
    s5 = [i for i in key["items"] if i["stratum"] == "S5_always_flag"]
    assert s5 and all(i["health"] is None and i["always_flag"] for i in s5)


def test_ssn_validity(built):
    _, key = built
    for i in key["items"]:
        if "ssn" in i["identifiers"] and _positive(i):
            assert SSN.match(i["value"]) and _valid_ssn(i["value"]), i["value"]
        if i["stratum"] == "N4_reserved_synthetic_value" and "ssn" in i["identifiers"]:
            assert _reserved_ssn(i["value"]), i["value"]


def test_s6_obfuscation(built):
    _, key = built
    s6 = [i for i in key["items"] if i["stratum"] == "S6_obfuscated"]
    assert set(Counter(i["obfuscation"] for i in s6).values()) == {20}
    assert len({i["obfuscation"] for i in s6}) == 8
    assert all(i["raw"] != i["value"] for i in s6)


def test_s4_containers_open(built):
    root, key = built
    for i in key["items"]:
        if i["stratum"] != "S4_documents":
            continue
        data = (root / "a" / i["file"]).read_bytes()
        if i["format"] == "pdf":
            reader = PdfReader(io.BytesIO(data))
            assert len(reader.pages) == 1
        elif i["format"] in ("docx", "xlsx", "pptx"):
            assert zipfile.ZipFile(io.BytesIO(data)).testzip() is None
        else:
            assert data[:2] == b"\xff\xd8" and data[-2:] == b"\xff\xd9"
