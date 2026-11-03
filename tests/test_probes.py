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


def test_one_record_across_several_elements(tmp_path, monkeypatch):
    from probes_prose import LAYOUT_NAME, LAYOUTS

    monkeypatch.setenv("PHI_EVIDENCE_KEYS", str(tmp_path / "keys"))
    src = tmp_path / "src"
    src.mkdir()
    for name, body in LAYOUTS.items():
        (src / f"{name}.html").write_text(f"<html><body>{body}<p>Thanks.</p></body></html>",
                                          encoding="utf-8")
    collect(src, tmp_path / "run")
    findings = [f for f in detect(tmp_path / "run" / "index.jsonl", tmp_path / "run" / "vault", (),
                                  context="public-web") if f["level"] != "review"]
    vault = Vault(tmp_path / "run" / "vault")
    missed = [name for name in LAYOUTS
              if not any(vault.token(LAYOUT_NAME) in f["value_hashes"]
                         for f in findings if f["path"] == f"{name}.html")]
    assert missed == []


def test_consented_testimonial_layouts(tmp_path, monkeypatch):
    from probes_prose import (CARD_WITHOUT_NOTE, CITE_QUOTE, CITE_QUOTE_NO_NOTE, CONSENT_LAYOUTS,
                              MULTI_BLOCK_CONSENT, TWO_STORIES)

    monkeypatch.setenv("PHI_EVIDENCE_KEYS", str(tmp_path / "keys"))
    src = tmp_path / "src"
    src.mkdir()
    clean = dict(CONSENT_LAYOUTS, **MULTI_BLOCK_CONSENT, cite_quote=CITE_QUOTE)
    pages = dict(clean, two_stories=TWO_STORIES, card_without_note=CARD_WITHOUT_NOTE,
                 cite_quote_no_note=CITE_QUOTE_NO_NOTE)
    for name, body in pages.items():
        (src / f"{name}.html").write_text(f"<html><body><h1>Stories</h1>{body}</body></html>",
                                          encoding="utf-8")
    collect(src, tmp_path / "run")
    findings = [f for f in detect(tmp_path / "run" / "index.jsonl", tmp_path / "run" / "vault", (),
                                  context="public-web") if f["level"] != "review"]
    vault = Vault(tmp_path / "run" / "vault")
    flagged = [name for name in clean if any(f["path"] == f"{name}.html" for f in findings)]
    two = [f for f in findings if f["path"] == "two_stories.html"]
    assert flagged == []
    assert any(vault.token("Ana Ruiz") in f["value_hashes"] for f in two)
    assert not any(vault.token("Priya Nair") in f["value_hashes"] for f in two)
    assert any(f["path"] == "card_without_note.html" for f in findings)
    assert any(f["path"] == "cite_quote_no_note.html" for f in findings)
