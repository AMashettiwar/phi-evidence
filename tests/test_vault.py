import json

import pytest

from phi_scan.vault import Vault, VaultExpired


@pytest.fixture(autouse=True)
def keys_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("PHI_EVIDENCE_KEYS", str(tmp_path / "keys"))


def test_round_trip_and_no_plaintext_on_disk(tmp_path):
    vault = Vault(tmp_path / "v")
    address = vault.put(b"Freya Bhatt MRN-881781")
    assert vault.get(address) == b"Freya Bhatt MRN-881781"
    on_disk = b"".join(p.read_bytes() for p in (tmp_path / "v").rglob("*") if p.is_file())
    assert b"Freya" not in on_disk and b"881781" not in on_disk


def test_key_lives_outside_the_vault_and_reopens(tmp_path):
    address = Vault(tmp_path / "v").put(b"x" * 40)
    assert not list((tmp_path / "v").rglob("*.key"))
    assert Vault(tmp_path / "v").get(address) == b"x" * 40


def test_addresses_and_tokens_are_keyed(tmp_path):
    one, two = Vault(tmp_path / "a"), Vault(tmp_path / "b")
    assert one.address(b"MRN-881781") != two.address(b"MRN-881781")
    assert one.token("123-45-6789") != two.token("123-45-6789")
    assert one.token("123-45-6789") == one.token("123-45-6789")


def test_every_read_is_logged(tmp_path):
    vault = Vault(tmp_path / "v")
    address = vault.put(b"evidence")
    vault.get(address, purpose="replay")
    entry = json.loads((tmp_path / "v" / "access.log").read_text().splitlines()[-1])
    assert entry["purpose"] == "replay" and entry["object"] == address


def test_expired_vault_refuses_reads(tmp_path):
    vault = Vault(tmp_path / "v")
    address = vault.put(b"evidence")
    vault.meta["expires"] = "2000-01-01T00:00:00+00:00"
    with pytest.raises(VaultExpired):
        vault.get(address)


def test_destroy_shreds_the_key(tmp_path):
    vault = Vault(tmp_path / "v")
    vault.put(b"evidence")
    vault.destroy()
    with pytest.raises(FileNotFoundError):
        Vault(tmp_path / "v")
