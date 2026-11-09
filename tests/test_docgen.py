import io
import struct
import sys
import zipfile
from pathlib import Path

from pypdf import PdfReader

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fixtures"))
import docgen  # noqa: E402

MARK = "Zq7Marker"


def _open(data: bytes) -> zipfile.ZipFile:
    archive = zipfile.ZipFile(io.BytesIO(data))
    assert archive.testzip() is None
    assert all(i.compress_type == zipfile.ZIP_STORED for i in archive.infolist())
    return archive


def _once(data: bytes, text: str = MARK) -> None:
    assert data.count(text.encode("utf-8")) == 1


XLSX = lambda: docgen.build_xlsx([  # noqa: E731
    {"name": "Open", "rows": [["a", "b"]], "hidden": False},
    {"name": "Secret", "rows": [["x", MARK]], "hidden": True}])
DOCX = lambda: docgen.build_docx(  # noqa: E731
    ["Plain text."], deleted=[MARK + "del"], inserted=[MARK + "ins"],
    core={"creator": MARK + "cr", "subject": MARK + "sub"})
PPTX = lambda: docgen.build_pptx([{"text": MARK + "t", "notes": MARK + "n"}])  # noqa: E731
JPEG = lambda: docgen.build_jpeg({"ImageDescription": MARK, "Artist": "Ann"})  # noqa: E731
PDF = lambda: docgen.build_pdf(["Hello " + MARK], {"Author": MARK + "au"})  # noqa: E731


def test_every_builder_is_deterministic():
    for build in (XLSX, DOCX, PPTX, JPEG, PDF):
        assert build() == build()


def test_pdf_extracts_text_and_metadata():
    reader = PdfReader(io.BytesIO(PDF()))
    assert MARK in reader.pages[0].extract_text()
    assert reader.metadata["/Author"] == MARK + "au"
    _once(PDF(), MARK + "au")


def test_xlsx_hidden_sheet_and_verbatim_value():
    data = XLSX()
    archive = _open(data)
    assert 'state="hidden"' in archive.read("xl/workbook.xml").decode()
    assert archive.read("xl/workbook.xml").decode().count("hidden") == 1
    assert "[Content_Types].xml" in archive.namelist()
    _once(data)


def test_docx_tracked_changes_and_core():
    data = DOCX()
    archive = _open(data)
    document = archive.read("word/document.xml").decode()
    assert f"<w:delText" in document and document.index("<w:delText") < document.index(MARK + "del")
    assert "<w:ins " in document
    assert f"<dc:creator>{MARK}cr</dc:creator>" in archive.read("docProps/core.xml").decode()
    for text in ("del", "ins", "cr", "sub"):
        _once(data, MARK + text)


def test_pptx_slide_and_notes():
    data = PPTX()
    archive = _open(data)
    assert MARK + "t" in archive.read("ppt/slides/slide1.xml").decode()
    assert MARK + "n" in archive.read("ppt/notesSlides/notesSlide1.xml").decode()
    _once(data, MARK + "t")
    _once(data, MARK + "n")


def test_jpeg_exif_ifd0_holds_the_marker():
    data = JPEG()
    assert data[:2] == b"\xff\xd8" and data[-2:] == b"\xff\xd9"
    assert data[2:4] == b"\xff\xe1" and data[6:12] == b"Exif\x00\x00"
    tiff = data[12:]
    assert tiff[:4] == b"II*\x00"
    count = struct.unpack_from("<H", tiff, 8)[0]
    found = {}
    for i in range(count):
        tag, kind, n, ptr = struct.unpack_from("<HHII", tiff, 10 + 12 * i)
        found[tag] = tiff[ptr:ptr + n] if n > 4 else tiff[10 + 12 * i + 8:10 + 12 * i + 8 + n]
    assert found[0x010E] == MARK.encode() + b"\x00"
    assert found[0x013B] == b"Ann\x00"
    assert list(found) == sorted(found)
    _once(data)
