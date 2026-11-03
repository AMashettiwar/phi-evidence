"""Encrypted, access-logged, expiring store for captured bytes.

Why a vault: the index that later stages work from must contain no patient
values. It contains only an address, an offset, and a length. The bytes live
here, so an evidence pointer can be replayed and verified and nothing in the
working set is readable PHI.

Each scan gets its own 32-byte key, kept outside the artifact tree (brief 4.5,
spec 2.8). The key does three jobs:

  * addresses are HMAC-SHA256(key, bytes). A plain SHA-256 of a short value is
    reversible by brute force: there are only a billion SSNs.
  * objects are encrypted with AES-256-GCM, the address bound in as associated
    data, so an object cannot be swapped for another.
  * token(value) is the HMAC-tokenised form of an identifier, used wherever a
    finding needs to say "this exact value" without holding it.

Every read is appended to access.log with who and why. After the retention
date reads are refused, and destroy() deletes the objects and the key, which
makes any copy of the ciphertext unreadable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TTL_DAYS = 30


def key_store() -> Path:
    return Path(os.environ.get("PHI_EVIDENCE_KEYS", Path.home() / ".phi-evidence" / "keys"))


class VaultExpired(Exception):
    pass


class Vault:
    def __init__(self, root: Path, key: bytes | None = None, actor: str = "phi-scan") -> None:
        self.root = Path(root)
        self.actor = actor
        self.written = 0
        self.reused = 0
        meta_path = self.root / "vault.json"
        if meta_path.exists():
            self.meta = json.loads(meta_path.read_text(encoding="utf-8"))
            self.key = key or (key_store() / f"{self.meta['key_id']}.key").read_bytes()
        else:
            self.key = key or os.urandom(32)
            now = datetime.now(timezone.utc)
            self.meta = {
                "key_id": hashlib.sha256(self.key).hexdigest()[:16],
                "cipher": "AES-256-GCM",
                "addressing": "HMAC-SHA256",
                "created": now.isoformat(timespec="seconds"),
                "expires": (now + timedelta(days=TTL_DAYS)).isoformat(timespec="seconds"),
            }
            store = key_store()
            store.mkdir(parents=True, exist_ok=True)
            (store / f"{self.meta['key_id']}.key").write_bytes(self.key)
            (self.root / "objects").mkdir(parents=True, exist_ok=True)
            meta_path.write_text(json.dumps(self.meta, indent=2) + "\n", encoding="utf-8")
        self._aead = AESGCM(self.key)

    def _path(self, address: str) -> Path:
        return self.root / "objects" / address[:2] / address

    def address(self, data: bytes) -> str:
        return hmac.new(self.key, data, hashlib.sha256).hexdigest()

    def token(self, value: str) -> str:
        """The tokenised form of an identifier: stable within this scan only."""
        return hmac.new(self.key, b"value\0" + value.encode("utf-8"), hashlib.sha256).hexdigest()

    def put(self, data: bytes) -> str:
        """Store bytes and return their address. Identical bytes are stored once."""
        address = self.address(data)
        target = self._path(address)
        if target.exists():
            self.reused += 1
            return address
        target.parent.mkdir(parents=True, exist_ok=True)
        nonce = os.urandom(12)
        target.write_bytes(nonce + self._aead.encrypt(nonce, data, address.encode()))
        self.written += 1
        return address

    def get(self, address: str, purpose: str = "detect") -> bytes:
        if datetime.now(timezone.utc) > datetime.fromisoformat(self.meta["expires"]):
            raise VaultExpired(f"vault {self.root} expired on {self.meta['expires']}")
        blob = self._path(address).read_bytes()
        with (self.root / "access.log").open("a", encoding="utf-8") as log:
            log.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                  "actor": self.actor, "purpose": purpose,
                                  "object": address}) + "\n")
        return self._aead.decrypt(blob[:12], blob[12:], address.encode())

    def has(self, address: str) -> bool:
        return self._path(address).exists()

    def destroy(self) -> None:
        """Delete every object and the key. The log of what existed stays."""
        shutil.rmtree(self.root / "objects", ignore_errors=True)
        (key_store() / f"{self.meta['key_id']}.key").unlink(missing_ok=True)
        with (self.root / "access.log").open("a", encoding="utf-8") as log:
            log.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                  "actor": self.actor, "purpose": "destroy"}) + "\n")
