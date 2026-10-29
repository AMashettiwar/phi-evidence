"""Content-addressed store for captured bytes.

Why a vault: the index that later stages work from must contain no patient
values. It contains only a digest, an offset, and a length. The bytes live here,
addressed by their hash, so an evidence pointer can be replayed and verified and
nothing in the working set is readable PHI.

A real deployment encrypts this directory and gives it a retention clock. The
interface is the same either way.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


class Vault:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        (self.root / "objects").mkdir(parents=True, exist_ok=True)
        self.written = 0
        self.reused = 0

    def _path(self, digest: str) -> Path:
        return self.root / "objects" / digest[:2] / digest

    def put(self, data: bytes) -> str:
        """Store bytes and return their digest. Identical bytes are stored once."""
        digest = hashlib.sha256(data).hexdigest()
        target = self._path(digest)
        if target.exists():
            self.reused += 1
            return digest
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        self.written += 1
        return digest

    def get(self, digest: str) -> bytes:
        return self._path(digest).read_bytes()

    def has(self, digest: str) -> bool:
        return self._path(digest).exists()
