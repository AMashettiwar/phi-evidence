"""Positional output: one span per occurrence, plus redaction.

Two jobs:

  write_findings  emit every finding with a position a consumer can act on —
                  code-point offsets for text files, the value itself for
                  binary files where there is no reliable character offset, and
                  a per-document verdict.

  write_redacted  write copies with the identified spans replaced, so the output
                  can be tested by rescanning it.

Redaction replaces the whole record the identifier sits in, not just the one
value we located. We can say where one value is; we cannot say where the other
identifiers in the same record are, and a redaction that left them behind would
be a false claim of safety.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

TEXT_SUFFIXES = {
    ".txt", ".md", ".html", ".htm", ".csv", ".json", ".jsonl", ".xml", ".log",
    ".sql", ".env", ".css", ".js", ".hl7", ".x12", ".yaml", ".yml", ".eml",
    ".patch", ".dcm",
}


def _is_text(path: str) -> bool:
    return Path(path).suffix.lower() in TEXT_SUFFIXES


def _char_offset(payload: bytes, byte_offset: int) -> int:
    """Code-point offset of a byte offset in UTF-8 text."""
    return len(payload[:byte_offset].decode("utf-8", "ignore"))


def write_findings(findings: list[dict], index_path: Path, vault_root: Path,
                   out: Path) -> int:
    from .vault import Vault  # noqa: PLC0415

    vault = Vault(vault_root)
    rows = {json.loads(line)["obs_id"]: json.loads(line)
            for line in Path(index_path).read_text(encoding="utf-8").splitlines() if line}
    docs: dict[str, bytes] = {}

    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    written = 0
    per_doc = defaultdict(bool)

    for finding in findings:
        payload = docs.get(finding["doc"])
        if payload is None:
            payload = vault.get(finding["doc"])
            docs[finding["doc"]] = payload
        per_doc[finding["path"]] = True

        if _is_text(finding["path"]):
            start = _char_offset(payload, finding["offset"])
            end = start + len(payload[finding["offset"]:finding["offset"] + finding["length"]]
                              .decode("utf-8", "ignore"))
            lines.append(json.dumps({"doc": finding["path"], "start": start, "end": end}))
        else:
            raw = payload[finding["offset"]:finding["offset"] + finding["length"]]
            lines.append(json.dumps({"doc": finding["path"],
                                     "text": raw.decode("utf-8", "ignore")}))
        written += 1

    for path in sorted(per_doc):
        lines.append(json.dumps({"doc": path, "has_phi": True}))

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return written


def write_redacted(findings: list[dict], source: Path, out: Path) -> int:
    """Copy the tree, then blank the record each identifier sits in."""
    from .vault import Vault  # noqa: PLC0415

    source = Path(source)
    out = Path(out)
    spans: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for finding in findings:
        spans[finding["path"]].append((finding["context_offset"],
                                       finding["context_offset"] + finding["context_length"]))

    written = 0
    dropped: list[str] = []
    for path in source.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(source).as_posix()
        data = path.read_bytes()
        if rel in spans and not _is_text(rel):
            # A binary container cannot be byte-patched without corrupting it.
            # Removing the file is the honest redaction; a mutated PDF that no
            # longer parses is worse than no file at all.
            dropped.append(rel)
            continue
        if rel in spans:
            # Conservative: a document that holds a finding is redacted in full.
            # We can say where one identifier is; we cannot prove the rest of the
            # document is clean, and a partial redaction would claim safety it
            # cannot demonstrate.
            data = b"*" * len(data)
        else:
            for start, end in sorted(spans.get(rel, []), key=lambda s: s[0], reverse=True):
                start = max(0, min(start, len(data)))
                end = max(start, min(end, len(data)))
                if end > start:
                    data = data[:start] + b"*" * (end - start) + data[end:]
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        written += 1

    if dropped:
        (out / "REMOVED.txt").write_text(
            "These binary containers were removed rather than patched, because\n"
            "byte-level redaction corrupts them:\n\n" + "\n".join(sorted(dropped)) + "\n",
            encoding="utf-8")
    return written
