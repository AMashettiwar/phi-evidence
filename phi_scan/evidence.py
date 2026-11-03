"""The evidence chain: what a scan writes, and how anyone can check it (brief 3).

Two outputs, because they answer different questions.

findings.json is canonical. It holds only what a reviewer needs and what a
second run must reproduce byte for byte: where, what kind, how bad, which rule,
a masked value. No vault address, no token, no timestamp, since all of those
change with the per-scan key or the clock and would make "the same scan gives
the same answer" untestable.

evidence.jsonl is this run's chain of custody. For every finding it records the
vault object, the span, an HMAC of the span's bytes, the tool and model
versions, and the command that replays it. replay() re-reads each span from the
vault and recomputes the HMAC: equal means the bytes behind the finding are the
bytes that were captured.
"""

from __future__ import annotations

import json
import platform
from pathlib import Path

from . import __version__
from .vault import Vault

CANONICAL_FIELDS = ("finding_id", "path", "carrier", "extraction", "offset", "length",
                    "context_offset", "context_length", "identifiers", "sensitive",
                    "value_mask", "level", "rules", "evidence_grade")


def canonical(findings: list[dict]) -> bytes:
    rows = [{field: finding[field] for field in CANONICAL_FIELDS if field in finding}
            for finding in findings]
    return (json.dumps(rows, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def versions() -> dict:
    import spacy  # noqa: PLC0415

    from .detect import _load_model  # noqa: PLC0415

    model = _load_model().meta
    return {"phi_scan": __version__, "python": platform.python_version(),
            "spacy": spacy.__version__, "ner_model": f"{model['lang']}_{model['name']}-{model['version']}"}


def write(out: Path, findings: list[dict], vault: Vault) -> dict:
    out = Path(out)
    (out / "findings.json").write_bytes(canonical(findings))
    tool = versions()
    with (out / "evidence.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for finding in findings:
            span = vault.get(finding["doc"], purpose="evidence")[
                finding["offset"]:finding["offset"] + finding["length"]]
            handle.write(json.dumps({
                "finding_id": finding["finding_id"],
                "object": finding["doc"],
                "offset": finding["offset"],
                "length": finding["length"],
                "span_hmac": vault.address(span),
                "value_tokens": finding["value_hashes"],
                "versions": tool,
                "replay": f"python -m phi_scan.cli replay {out.as_posix()} --finding {finding['finding_id']}",
            }, sort_keys=True) + "\n")
    return {"findings": len(findings), "versions": tool}


def replay(out: Path, only: str | None = None) -> dict:
    """Re-read every finding's span from the vault and check its HMAC."""
    out = Path(out)
    vault = Vault(out / "vault", actor="replay")
    checked, mismatched = 0, []
    for line in (out / "evidence.jsonl").read_text(encoding="utf-8").splitlines():
        entry = json.loads(line)
        if only and entry["finding_id"] != only:
            continue
        data = vault.get(entry["object"], purpose="replay")
        span = data[entry["offset"]:entry["offset"] + entry["length"]]
        checked += 1
        if vault.address(span) != entry["span_hmac"]:
            mismatched.append(entry["finding_id"])
    return {"checked": checked, "identical": checked - len(mismatched), "mismatched": mismatched}
