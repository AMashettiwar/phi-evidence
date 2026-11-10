"""Tests for deep multi-modal ingestion: scanned PDFs (OCR), unflattened PDF
redactions, PDF annotations/form fields, raster image OCR, DICOM pixel OCR,
RTF clinical notes, MIME .eml emails with attachments, and recursive archives."""

from __future__ import annotations

from email.message import EmailMessage
import io
from pathlib import Path
import tarfile
import zipfile

import pymupdf as fitz
from PIL import Image, ImageDraw, ImageFont

from phi_scan.collect import collect
from phi_scan.detect import detect
from phi_scan.positions import redact_pdf_bytes, write_redacted


def _render_text_png(line: str) -> bytes:
    """Create a high-contrast PNG with burned-in text for OCR."""
    img = Image.new("RGB", (900, 140), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 28)
    except Exception:  # noqa: BLE001
        font = ImageFont.load_default()
    draw.text((24, 45), line, fill=(0, 0, 0), font=font)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_scanned_pdf_ocr_and_true_pdf_redaction(tmp_path: Path) -> None:
    """An image-only scanned PDF with zero native text layer is read via OCR,
    and redact_pdf_bytes strips the image so rescanning yields 0 findings."""
    src = tmp_path / "src"
    src.mkdir()
    png_bytes = _render_text_png("Patient: Emeka Delgado MRN-881001 Diagnosis: carcinoma")

    doc = fitz.open()
    page = doc.new_page(width=612, height=792)
    page.insert_image(fitz.Rect(36, 100, 576, 220), stream=png_bytes)
    pdf_path = src / "scanned_chart.pdf"
    pdf_path.write_bytes(doc.tobytes())
    doc.close()

    out = tmp_path / "out"
    collect(src, out)
    findings = detect(out / "index.jsonl", out / "vault", context="public-web")
    assert findings, "Expected scanned image-only PDF to be caught via OCR"
    assert any(f["path"] == "scanned_chart.pdf" for f in findings)

    # Now perform true PDF redaction and verify valid PDF + 0 findings on rescan
    redacted_bytes = redact_pdf_bytes(pdf_path.read_bytes())
    assert redacted_bytes is not None and redacted_bytes.startswith(b"%PDF-")
    redacted_dir = tmp_path / "redacted"
    redacted_dir.mkdir()
    (redacted_dir / "scanned_chart.pdf").write_bytes(redacted_bytes)

    recheck = tmp_path / "recheck"
    collect(redacted_dir, recheck)
    again = detect(recheck / "index.jsonl", recheck / "vault", context="public-web")
    assert again == []


def test_pdf_unflattened_faux_redaction_and_annotations(tmp_path: Path) -> None:
    """Text covered by a black rectangle without glyph removal, and text inside
    a PDF sticky-note annotation, are both extracted and flagged."""
    src = tmp_path / "src"
    src.mkdir()

    doc = fitz.open()
    page = doc.new_page(width=612, height=792)
    rect = fitz.Rect(72, 100, 450, 130)
    page.insert_text((72, 120), "Marisol Lindqvist MRN-884210 stage III lymphoma", fontsize=12)
    # Draw a solid black box directly over the text (faux redaction)
    shape = page.new_shape()
    shape.draw_rect(rect)
    shape.finish(fill=(0, 0, 0), color=(0, 0, 0))
    shape.commit()

    # Add a sticky-note annotation carrying another patient record
    page.add_text_annot((100, 200), "Patient: Yuki Rahimi MRN-991204 multiple sclerosis")
    pdf_bytes = doc.tobytes()
    doc.close()

    (src / "faux_redacted.pdf").write_bytes(pdf_bytes)
    out = tmp_path / "out"
    collect(src, out)
    findings = detect(out / "index.jsonl", out / "vault", context="public-web")
    extractions = {f["extraction"] for f in findings}
    assert "pdf_unflattened_redaction" in extractions or "pdf_text_layer" in extractions
    assert "pdf_annotations" in extractions


def test_raster_image_ocr(tmp_path: Path) -> None:
    """A standalone PNG screenshot with burned-in patient PHI is read via OCR."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "screenshot.png").write_bytes(
        _render_text_png("Patient: Ingrid Vasquez MRN-773190 hepatitis C")
    )
    out = tmp_path / "out"
    collect(src, out)
    findings = detect(out / "index.jsonl", out / "vault", context="public-web")
    assert any(f["path"] == "screenshot.png" and f["extraction"] == "image_ocr" for f in findings)


def test_rtf_eml_and_nested_archives(tmp_path: Path) -> None:
    """RTF clinical letters, .eml emails with attachments, and .zip/.tar.gz
    archives are recursively unpacked and scanned."""
    src = tmp_path / "src"
    src.mkdir()

    # 1. RTF document
    rtf = (
        r"{\rtf1\ansi{\fonttbl\f0 Arial;}\f0\pard "
        r"Patient: Beatrix Yamamoto \par MRN-662109 \par Diagnosis: ovarian carcinoma \par}"
    )
    (src / "referral.rtf").write_text(rtf, encoding="utf-8")

    # 2. MIME .eml with body and CSV attachment
    msg = EmailMessage()
    msg["Subject"] = "Urgent consult"
    msg["From"] = "clinic@hospital.example"
    msg["To"] = "oncology@hospital.example"
    msg.set_content("Consult note for Tobias Feng (MRN-551908) diagnosed with bipolar disorder.")
    msg.add_attachment(
        b"patient_name,mrn,diagnosis\nPriya Raghunathan,MRN-441807,chronic kidney disease\n",
        maintype="text",
        subtype="csv",
        filename="attached_roster.csv",
    )
    (src / "consult.eml").write_bytes(msg.as_bytes())

    # 3. Nested .zip and .tar.gz archives
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("inner/note.txt", "Patient: Clara Watanabe MRN-331706 major depressive disorder\n")
    (src / "export_bundle.zip").write_bytes(zip_buf.getvalue())

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
        payload = b'{"patient_name": "Noor Haddad", "mrn": "MRN-221605", "condition": "breast carcinoma"}'
        info = tarfile.TarInfo(name="dump/patient.json")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    (src / "backup.tar.gz").write_bytes(tar_buf.getvalue())

    out = tmp_path / "out"
    collect(src, out)
    findings = detect(out / "index.jsonl", out / "vault", context="public-web")
    paths = {f["path"] for f in findings}
    assert "referral.rtf" in paths
    assert "consult.eml" in paths
    assert "export_bundle.zip" in paths
    assert "backup.tar.gz" in paths


def test_removed_note_is_written_when_only_binaries_are_dropped(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "scan.png").write_bytes(b"\x89PNG\r\nnot-a-real-image")
    findings = [{
        "path": "scan.png",
        "context_offset": 0,
        "context_length": 4,
    }]
    out = tmp_path / "redacted"
    written = write_redacted(findings, source, out)
    note = (out / "REMOVED.txt").read_text(encoding="utf-8")
    assert written == 0
    assert "scan.png" in note
