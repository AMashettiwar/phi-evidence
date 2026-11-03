"""Byte-exact builders for the document formats a real exam is made of.

Everything here is pure and deterministic: the same input gives the same bytes.
That matters because the corpus key records a byte offset for every planted
value, and a rebuild must not move it.

Two rules make the offsets trustworthy:
  - every text value appears verbatim as UTF-8 in the output, so
    `data.find(value.encode("utf-8"))` is its offset;
  - zip containers (xlsx, docx, pptx) store members uncompressed with a fixed
    timestamp. Deflate would hide the value; a real timestamp would break
    reproducibility.

Values are XML-escaped, which is a no-op for text without & < > ".
"""

from __future__ import annotations

import io
import struct
import zipfile
from xml.sax.saxutils import escape

_EPOCH = (1980, 1, 1, 0, 0, 0)
_XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_CT = "http://schemas.openxmlformats.org/package/2006/content-types"
_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_A = "http://schemas.openxmlformats.org/drawingml/2006/main"
_CORE_REL = _PKG_REL + "/metadata/core-properties"
_P = "http://schemas.openxmlformats.org/presentationml/2006/main"


def _zip(members: list[tuple[str, str]]) -> bytes:
    """Stored (uncompressed), fixed-timestamp zip, members in the order given."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name, text in members:
            info = zipfile.ZipInfo(name, date_time=_EPOCH)
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, (_XML + text).encode("utf-8"))
    return buffer.getvalue()


def _types(overrides: list[tuple[str, str]]) -> str:
    rows = "".join(f'<Override PartName="/{part}" ContentType="{ct}"/>' for part, ct in overrides)
    return (f'<Types xmlns="{_CT}"><Default Extension="rels" '
            'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            f'<Default Extension="xml" ContentType="application/xml"/>{rows}</Types>')


def _rels(rows: list[tuple[str, str, str]]) -> str:
    body = "".join(
        f'<Relationship Id="{i}" Type="{kind if "/" in kind else _REL + "/" + kind}" '
        f'Target="{target}"/>' for i, kind, target in rows)
    return f'<Relationships xmlns="{_PKG_REL}">{body}</Relationships>'


def build_pdf(lines: list[str], info: dict[str, str]) -> bytes:
    """A small but valid PDF with an uncompressed text layer and /Info metadata."""
    objects: list[bytes] = []

    def add(body: bytes) -> None:
        objects.append(body)

    content = ["BT", "/F1 11 Tf", "72 700 Td"]
    for index, line in enumerate(lines):
        escaped = line.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
        if index:
            content.append("0 -20 Td")
        content.append(f"({escaped}) Tj")
    content.append("ET")
    stream = "\n".join(content).encode("latin-1")

    add(b"<< /Type /Catalog /Pages 2 0 R >>")
    add(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    add(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>")
    add(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")
    add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    info_body = "<< " + " ".join(f"/{k} ({v})" for k, v in info.items()) + " >>"
    add(info_body.encode("latin-1"))

    out = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_at = len(out)
    size = len(objects) + 1
    out += f"xref\n0 {size}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {size} /Root 1 0 R /Info {len(objects)} 0 R >>\n"
            f"startxref\n{xref_at}\n%%EOF\n").encode()
    return bytes(out)


def build_xlsx(sheets: list[dict]) -> bytes:
    """Workbook with inline-string cells, so values sit verbatim in the sheet XML."""
    parts = [(f"xl/worksheets/sheet{n}.xml", _sheet(s["rows"])) for n, s in enumerate(sheets, 1)]
    listed = "".join(
        f'<sheet name="{escape(s["name"])}" sheetId="{n}"'
        f'{" state=" + chr(34) + "hidden" + chr(34) if s.get("hidden") else ""} r:id="rId{n}"/>'
        for n, s in enumerate(sheets, 1))
    workbook = f'<workbook xmlns="{_MAIN}" xmlns:r="{_REL}"><sheets>{listed}</sheets></workbook>'
    sheet_ct = "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"
    return _zip([
        ("[Content_Types].xml", _types(
            [("xl/workbook.xml",
              "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml")]
            + [(name, sheet_ct) for name, _ in parts])),
        ("_rels/.rels", _rels([("rId1", "officeDocument", "xl/workbook.xml")])),
        ("xl/workbook.xml", workbook),
        ("xl/_rels/workbook.xml.rels", _rels(
            [(f"rId{n}", "worksheet", f"worksheets/sheet{n}.xml") for n in range(1, len(sheets) + 1)])),
        *parts,
    ])


def _sheet(rows: list[list[str]]) -> str:
    body = ""
    for r, row in enumerate(rows, 1):
        cells = "".join(
            f'<c r="{chr(65 + c)}{r}" t="inlineStr"><is><t>{escape(v)}</t></is></c>'
            for c, v in enumerate(row))
        body += f'<row r="{r}">{cells}</row>'
    return f'<worksheet xmlns="{_MAIN}"><sheetData>{body}</sheetData></worksheet>'


def build_docx(paragraphs: list[str], deleted: list[str] | None = None,
               inserted: list[str] | None = None,
               core: dict[str, str] | None = None) -> bytes:
    """Word document; deleted/inserted strings are tracked changes, one per paragraph."""
    stamp = 'w:author="Reviewer" w:date="2026-01-01T00:00:00Z"'
    body = "".join(f"<w:p><w:r><w:t>{escape(t)}</w:t></w:r></w:p>" for t in paragraphs)
    change_id = 0
    for text in deleted or []:
        change_id += 1
        body += (f'<w:p><w:del w:id="{change_id}" {stamp}><w:r>'
                 f'<w:delText xml:space="preserve">{escape(text)}</w:delText></w:r></w:del></w:p>')
    for text in inserted or []:
        change_id += 1
        body += (f'<w:p><w:ins w:id="{change_id}" {stamp}><w:r>'
                 f'<w:t>{escape(text)}</w:t></w:r></w:ins></w:p>')
    document = f'<w:document xmlns:w="{_W}"><w:body>{body}</w:body></w:document>'
    tags = {"creator": "dc", "title": "dc", "subject": "dc", "description": "dc",
            "keywords": "cp", "lastModifiedBy": "cp"}
    props = "".join(f"<{tags[k]}:{k}>{escape(v)}</{tags[k]}:{k}>"
                    for k, v in (core or {}).items() if k in tags)
    core_xml = ('<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/'
                'metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">'
                f'{props}</cp:coreProperties>')
    return _zip([
        ("[Content_Types].xml", _types([
            ("word/document.xml",
             "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"),
            ("docProps/core.xml", "application/vnd.openxmlformats-package.core-properties+xml")])),
        ("_rels/.rels", _rels([
            ("rId1", "officeDocument", "word/document.xml"),
            ("rId2", _CORE_REL, "docProps/core.xml")])),
        ("word/document.xml", document),
        ("docProps/core.xml", core_xml),
    ])


def build_pptx(slides: list[dict]) -> bytes:
    """Presentation: each slide holds `text`, and its notes page holds `notes`."""
    count = range(1, len(slides) + 1)
    ids = "".join(f'<p:sldId id="{255 + n}" r:id="rId{n}"/>' for n in count)
    presentation = (f'<p:presentation xmlns:p="{_P}" xmlns:r="{_REL}" xmlns:a="{_A}">'
                    f'<p:sldIdLst>{ids}</p:sldIdLst></p:presentation>')
    members: list[tuple[str, str]] = []
    overrides = [("ppt/presentation.xml",
                  "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml")]
    for n, slide in zip(count, slides):
        overrides.append((f"ppt/slides/slide{n}.xml",
                          "application/vnd.openxmlformats-officedocument.presentationml.slide+xml"))
        overrides.append((f"ppt/notesSlides/notesSlide{n}.xml",
                          "application/vnd.openxmlformats-officedocument.presentationml.notesSlide+xml"))
        members += [
            (f"ppt/slides/slide{n}.xml", _shape_tree("sld", slide["text"])),
            (f"ppt/slides/_rels/slide{n}.xml.rels",
             _rels([("rId1", "notesSlide", f"../notesSlides/notesSlide{n}.xml")])),
            (f"ppt/notesSlides/notesSlide{n}.xml", _shape_tree("notes", slide["notes"])),
            (f"ppt/notesSlides/_rels/notesSlide{n}.xml.rels",
             _rels([("rId1", "slide", f"../slides/slide{n}.xml")])),
        ]
    return _zip([
        ("[Content_Types].xml", _types(overrides)),
        ("_rels/.rels", _rels([("rId1", "officeDocument", "ppt/presentation.xml")])),
        ("ppt/presentation.xml", presentation),
        ("ppt/_rels/presentation.xml.rels",
         _rels([(f"rId{n}", "slide", f"slides/slide{n}.xml") for n in count])),
        *members,
    ])


def _shape_tree(root: str, text: str) -> str:
    return (f'<p:{root} xmlns:p="{_P}" xmlns:a="{_A}" xmlns:r="{_REL}"><p:cSld><p:spTree>'
            '<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
            '<p:grpSpPr/><p:sp><p:nvSpPr><p:cNvPr id="2" name="Text"/><p:cNvSpPr/><p:nvPr/>'
            f'</p:nvSpPr><p:spPr/><p:txBody><a:bodyPr/><a:p><a:r><a:t>{escape(text)}</a:t></a:r>'
            f'</a:p></p:txBody></p:sp></p:spTree></p:cSld></p:{root}>')


# An 8x8 grey baseline JPEG built from first principles: all-ones quantiser, one-code
# Huffman tables (DC category 0, AC end-of-block), and a scan of the two bits "00".
_DQT = b"\xff\xdb\x00\x43\x00" + b"\x01" * 64
_SOF = b"\xff\xc0\x00\x0b\x08\x00\x08\x00\x08\x01\x01\x11\x00"
_DHT_DC = b"\xff\xc4\x00\x14\x00" + b"\x01" + b"\x00" * 15 + b"\x00"
_DHT_AC = b"\xff\xc4\x00\x14\x10" + b"\x01" + b"\x00" * 15 + b"\x00"
_SOS = b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00" + b"\x3f"
_EXIF_TAGS = {"ImageDescription": 0x010E, "Artist": 0x013B, "Software": 0x0131,
              "Copyright": 0x8298}


def build_jpeg(exif: dict[str, str]) -> bytes:
    """Tiny valid JPEG with a little-endian Exif APP1 right after SOI."""
    entries = sorted((_EXIF_TAGS[k], v.encode("utf-8") + b"\x00")
                     for k, v in exif.items() if k in _EXIF_TAGS)
    data_at = 8 + 2 + 12 * len(entries) + 4  # offsets are counted from the TIFF header
    ifd, blob = b"", b""
    for tag, value in entries:
        if len(value) <= 4:
            pointer = value.ljust(4, b"\x00")
        else:
            pointer = struct.pack("<I", data_at + len(blob))
            blob += value
        ifd += struct.pack("<HHI", tag, 2, len(value)) + pointer
    tiff = b"II*\x00" + struct.pack("<I", 8) + struct.pack("<H", len(entries)) + ifd \
        + b"\x00\x00\x00\x00" + blob
    app1 = b"Exif\x00\x00" + tiff
    return (b"\xff\xd8" + b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1
            + _DQT + _SOF + _DHT_DC + _DHT_AC + _SOS + b"\xff\xd9")
