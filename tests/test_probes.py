"""Independent prose probes (tests/probes_prose.py) as a regression test: every
positive caught by name, every negative clean."""

from pathlib import Path

from probes_prose import NEGATIVES, POSITIVES

from phi_scan.collect import collect
from phi_scan.detect import detect
from phi_scan.vault import Vault


def test_independent_prose_probes(tmp_path, monkeypatch):
    monkeypatch.setenv("PHI_EVIDENCE_KEYS", str(tmp_path / "keys"))
    src = tmp_path / "src"
    src.mkdir()
    for index, (_, text) in enumerate(POSITIVES):
        (src / f"p{index:02d}.html").write_text(
            f"<html><body><h1>News</h1><p>{text}</p><p>Thanks for visiting.</p></body></html>",
            encoding="utf-8")
    for index, text in enumerate(NEGATIVES):
        (src / f"n{index:02d}.html").write_text(
            f"<html><body><h1>News</h1><p>{text}</p></body></html>", encoding="utf-8")
    collect(src, tmp_path / "run")
    findings = [f for f in detect(tmp_path / "run" / "index.jsonl", tmp_path / "run" / "vault", (),
                                  context="public-web") if f["level"] != "review"]
    vault = Vault(tmp_path / "run" / "vault")
    missed = [name for index, (name, _) in enumerate(POSITIVES)
              if not any(vault.token(name) in f["value_hashes"]
                         for f in findings if f["path"] == f"p{index:02d}.html")]
    flagged = [text for index, text in enumerate(NEGATIVES)
               if any(f["path"] == f"n{index:02d}.html" for f in findings)]
    assert missed == [] and flagged == []
