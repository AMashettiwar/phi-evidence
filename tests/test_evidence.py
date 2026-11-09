import json

import pytest

from phi_scan.evidence import canonical, replay, write
from phi_scan.vault import Vault


@pytest.fixture(autouse=True)
def keys_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("PHI_EVIDENCE_KEYS", str(tmp_path / "keys"))


def finding(vault: Vault, text: bytes) -> dict:
    return {"finding_id": "f00001", "path": "site/a.html", "carrier": "page_text",
            "extraction": "text", "doc": vault.put(text), "offset": 4, "length": 11,
            "identifiers": ["names"], "value_mask": "******hatt", "level": "critical",
            "rules": ["permitted_disclosure"], "evidence_grade": "A",
            "value_hashes": [vault.token("Freya Bhatt")]}


def test_canonical_carries_no_token_address_or_value(tmp_path):
    vault = Vault(tmp_path / "v")
    out = canonical([finding(vault, b"Pt: Freya Bhatt, dx")]).decode()
    assert "Freya" not in out and vault.token("Freya Bhatt") not in out
    assert '"doc"' not in out and "value_hashes" not in out


def test_canonical_is_the_same_under_two_keys(tmp_path):
    one, two = Vault(tmp_path / "a"), Vault(tmp_path / "b")
    text = b"Pt: Freya Bhatt, dx"
    assert canonical([finding(one, text)]) == canonical([finding(two, text)])


def test_replay_detects_tampering(tmp_path, monkeypatch):
    vault = Vault(tmp_path / "run" / "vault")
    item = finding(vault, b"Pt: Freya Bhatt, dx")
    monkeypatch.setattr("phi_scan.evidence.versions", lambda: {"phi_scan": "test"})
    write(tmp_path / "run", [item], vault)
    assert replay(tmp_path / "run") == {"checked": 1, "identical": 1, "mismatched": []}

    entry = json.loads((tmp_path / "run" / "evidence.jsonl").read_text())
    entry["offset"] = 5
    (tmp_path / "run" / "evidence.jsonl").write_text(json.dumps(entry) + "\n")
    assert replay(tmp_path / "run")["mismatched"] == ["f00001"]
