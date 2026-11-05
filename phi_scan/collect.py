"""Turn a source tree into evidence spans, without executing any of it.

The collector does not decide what is PHI. It decides what bytes exist, where
they sit, and which part of a page or file they came from. Detection is a
separate stage that reads the vault through these pointers.

Nothing in the output index contains a patient value. Every entry is a digest,
an offset, a length, and a label. That is what makes "never store raw PHI in the
default output" a property of the design rather than a promise.

Evidence grades:
    A  confirmed by capture (a recorded request or server log)
    B  present in source; transmission or storage not observed
    C  inferred from surrounding structure

Static collection can only produce B. That is deliberate, and it is reported.
"""

from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import json
import re
import sys
from pathlib import Path

from . import structured
from .vault import Vault

TAG = re.compile(r"<[^>]*>", re.S)
COMMENT = re.compile(r"<!--(.*?)-->", re.S)
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
META = re.compile(r"<meta[^>]*content\s*=\s*\"([^\"]*)\"", re.I)
DATA_ATTR = re.compile(r"\sdata-[\w-]+\s*=\s*\"([^\"]*)\"", re.I)
# An attribute whose value itself contains double quotes must be single-quoted.
DATA_ATTR_SINGLE = re.compile(r"\sdata-[\w-]+\s*=\s*'([^']*)'", re.I)
ARIA = re.compile(r"\saria-[\w]+\s*=\s*\"([^\"]*)\"", re.I)
HIDDEN_LEFT = re.compile(
    r"<(?:span|div)[^>]*style\s*=\s*\"[^\"]*left:\s*-\d{3,}px[^\"]*\"[^>]*>(.*?)</(?:span|div)>",
    re.S | re.I)
HIDDEN_NONE = re.compile(
    r"<(?:span|div)[^>]*style\s*=\s*\"[^\"]*display:\s*none[^\"]*\"[^>]*>(.*?)</(?:span|div)>",
    re.S | re.I)
INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.S | re.I)
SCRIPT_BLOCK = re.compile(r"<script[^>]*>.*?</script>", re.S | re.I)
STYLE_BLOCK = re.compile(r"<style[^>]*>.*?</style>", re.S | re.I)
ABS_URL = re.compile(r"(?:src|href)\s*=\s*\"(https?://[^\"]+)\"", re.I)
QUERY_URL = re.compile(r"href\s*=\s*\"([^\"]+\?[^\"]*)\"", re.I)
LOC = re.compile(r"<loc>(.*?)</loc>", re.S | re.I)
B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
STORAGE = re.compile(r"localStorage\.setItem\((.*?)\);", re.S)
PRINT = re.compile(r"@media\s+print", re.I)
# A stylesheet puts words on screen only through `content:`. The rest is code:
# on the first real app a font stack became a person and a colour (#283593) a
# record number.
CSS_CONTENT = re.compile(r"""\bcontent\s*:\s*(["'])((?:\\.|(?!\1)[^\\])*)\1""", re.S)
# The words an SVG draws (<text>, <title>, <desc>). Its attributes are drawing
# instructions: stroke="#0F7C93" read as the disease, font-family as a person.
SVG_TEXT = re.compile(r"<(?!style\b|script\b)[A-Za-z][\w:-]*\b[^>]*>([^<]*[^\s<][^<]*)", re.I)
ARIA_HIDDEN = re.compile(r"<(\w+)\b[^>]*\baria-hidden\s*=\s*[\"']true[\"'][^>]*>(.*?)</\1>",
                         re.S | re.I)
JSON_LD = re.compile(
    r"<script[^>]*type\s*=\s*[\"']application/ld\+json[\"'][^>]*>(.*?)</script>", re.S | re.I)
IDB_WRITE = re.compile(r"\.(?:put|add)\(")
COOKIE_SET = re.compile(r"document\.cookie\s*=(?!=)\s*")


def _grade(carrier: str) -> str:
    """Static extraction never earns an A."""
    return "B"


class Sink:
    def __init__(self, vault: Vault) -> None:
        self.vault = vault
        self.rows: list[dict] = []
        # Extractors work in character offsets; the vault holds bytes. Without a
        # per-document map, one non-ASCII character shifts every later span: the
        # zero-width test lost two characters off the end of its diagnosis.
        self.maps: dict[str, list[int]] = {}

    def add(self, path: str, doc: str, start: int, length: int, carrier: str,
            extraction: str, derivation: str = "raw") -> None:
        if length <= 0:
            return
        table = self.maps.get(doc)
        if table is not None and len(table) > 1:
            total = len(table) - 1
            begin = table[min(start, total)]
            end = table[min(start + length, total)]
            # Never let the conversion produce an empty span: an observation
            # that ends exactly at end-of-file would otherwise replay as nothing.
            begin = min(begin, total - 1)
            length = max(1, end - begin)
            start = begin
        self.rows.append({
            "path": path, "doc": doc, "offset": start, "length": length,
            "carrier": carrier, "extraction": extraction,
            "grade": _grade(carrier), "derivation": derivation,
        })


def _gaps(data: str, excluded: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Text between tags, skipping regions we already claimed (script/style/comment)."""
    spans: list[tuple[int, int]] = []
    cursor = 0
    for match in TAG.finditer(data):
        if match.start() > cursor:
            spans.append((cursor, match.start()))
        cursor = match.end()
    if cursor < len(data):
        spans.append((cursor, len(data)))

    kept: list[tuple[int, int]] = []
    for start, end in spans:
        inside = any(start >= lo and start < hi for lo, hi in excluded)
        if inside:
            continue
        raw = data[start:end]
        stripped = raw.strip()
        if not stripped:
            continue
        lead = len(raw) - len(raw.lstrip())
        kept.append((start + lead, len(stripped)))
    return kept


class _Node:
    __slots__ = ("tag", "attrs", "children")

    def __init__(self, tag: str, attrs: dict) -> None:
        self.tag, self.attrs, self.children = tag, attrs, []


class _Tree(HTMLParser):
    """A forgiving DOM: enough structure to know which element holds which text."""
    VOID = {"br", "img", "hr", "input", "meta", "link", "source", "wbr", "area", "col"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = _Node("root", {})
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = _Node(tag, dict(attrs))
        self.stack[-1].children.append(node)
        if tag not in self.VOID:
            self.stack.append(node)

    def handle_endtag(self, tag):
        for depth in range(len(self.stack) - 1, 0, -1):
            if self.stack[depth].tag == tag:
                del self.stack[depth:]
                return

    def handle_data(self, data):
        self.stack[-1].children.append(data)


# One record each, by element (spec 2.3 and the rulebook: a list item, a table
# row, a set of fields), plus a figure with its caption and a quotation.
RECORD_ELEMENTS = {"li", "tr", "dl", "figure", "blockquote", "fieldset", "form", "address"}
CONTAINERS = {"div", "section", "article", "aside"}
HEADINGS = {"h1", "h2", "h3", "h4", "h5", "h6"}
SKIP = {"script", "style", "noscript", "template", "head", "title"}
INLINE = {"span", "b", "i", "em", "strong", "a", "small", "sup", "sub", "font", "mark", "u",
          "s", "abbr", "code", "label", "cite", "time", "q"}


def _raw_text(node) -> str:
    """Text of a subtree, whitespace as written: inline elements join with
    nothing, <br> with a space, block children with a " | " separator, image
    alt text included. "Micheal </span><span>Choi" keeps its space."""
    if isinstance(node, str):
        return node
    if node.tag in SKIP:
        return ""
    if node.tag == "br":
        return " "
    if node.tag == "img":
        return f" {node.attrs.get('alt') or ''} "
    parts = []
    for child in node.children:
        piece = _raw_text(child)
        block = not isinstance(child, str) and child.tag not in INLINE and child.tag not in ("br", "img")
        parts.append(f" | {piece} | " if block and piece.strip() else piece)
    return "".join(parts)


def _text(node) -> str:
    """One record's text, whitespace collapsed once over the whole record."""
    joined = re.sub(r"(\s*\|\s*)+", " | ", _raw_text(node))
    return " ".join(joined.split()).strip(" |")


def _blocks(node) -> list:
    return [c for c in node.children if not isinstance(c, str) and c.tag not in INLINE
            and c.tag not in SKIP and c.tag not in ("br", "img")]


def _is_card(node) -> bool:
    """A small container about one subject: a heading or a lead element and at
    most two short blocks after it, with no records of its own inside."""
    blocks = _blocks(node)
    if not 2 <= len(blocks) <= 3 or len(_text(node)) > 300:
        return False
    if any(b.tag in RECORD_ELEMENTS or b.tag in CONTAINERS for b in blocks):
        return False
    return blocks[0].tag in HEADINGS or blocks[0].tag in ("p", "div") and len(_text(blocks[0])) <= 60


def _records(node, out: list[str]) -> None:
    for child in node.children:
        if isinstance(child, str):
            if child.strip():
                out.append(" ".join(child.split()))
            continue
        if child.tag in SKIP:
            continue
        if child.tag in RECORD_ELEMENTS or (child.tag in CONTAINERS and _is_card(child)):
            text = _text(child)
            if text:
                out.append(text)
        elif child.tag in INLINE or not _blocks(child):
            # An inline run, or a leaf block (a paragraph, a heading, a cell):
            # one record, with <br> as a space and split spans rejoined.
            text = _text(child)
            if text:
                out.append(text)
        else:
            _records(child, out)


def _rendered_text(text: str) -> str:
    """The page as a reader sees it, one record per line. A record is a list
    item, a table row, a definition list, a figure, a quotation, a set of form
    fields, an address, or a small card (a heading and a block or two); any
    other block is its own record. Inline tags vanish without a space, so a
    name split across spans ("Na</span><span>dia") is one word again."""
    tree = _Tree()
    try:
        tree.feed(text)
        tree.close()
    except Exception:  # noqa: BLE001 - malformed markup still yields what parsed
        pass
    lines: list[str] = []
    _records(tree.root, lines)
    return "\n".join(line for line in lines if line)


def _collect_html(path: str, text: str, doc: str, sink: Sink,
                  target_host: str | None = None) -> None:
    excluded: list[tuple[int, int]] = []
    rendered = _rendered_text(text)
    if rendered:
        encoded = rendered.encode("utf-8")
        sink.add(path, sink.vault.put(encoded), 0, len(encoded), "page_text", "rendered_text",
                 "rendered_text")

    for match in COMMENT.finditer(text):
        sink.add(path, doc, match.start(1), len(match.group(1)), "hidden_code", "html_comment")
        excluded.append((match.start(), match.end()))
    for match in STYLE_BLOCK.finditer(text):
        excluded.append((match.start(), match.end()))
    for match in SCRIPT_BLOCK.finditer(text):
        excluded.append((match.start(), match.end()))

    for match in TITLE.finditer(text):
        sink.add(path, doc, match.start(1), len(match.group(1)), "title", "html_title")
    for match in META.finditer(text):
        sink.add(path, doc, match.start(1), len(match.group(1)), "meta_tag", "meta_content")
    for pattern in (DATA_ATTR, DATA_ATTR_SINGLE, ARIA):
        for match in pattern.finditer(text):
            sink.add(path, doc, match.start(1), len(match.group(1)),
                     "html_attribute", "html_attribute_value")
    for match in HIDDEN_LEFT.finditer(text):
        sink.add(path, doc, match.start(1), len(match.group(1)), "css_hidden", "offscreen_element")
    for match in HIDDEN_NONE.finditer(text):
        sink.add(path, doc, match.start(1), len(match.group(1)), "hidden_code", "display_none")
    for match in INLINE_SCRIPT.finditer(text):
        body = match.group(1)
        if not body.strip():
            continue
        base = match.start(1)
        sink.add(path, doc, base, len(body), "inline_script", "script_body")
        # A storage call written inside the page is still a storage leak.
        for found in STORAGE.finditer(body):
            sink.add(path, doc, base + found.start(), len(found.group(0)),
                     "browser_storage", "set_item_call")
        for found in B64.finditer(body):
            sink.add(path, doc, base + found.start(), len(found.group(0)),
                     "encoded_value", "base64_like")
        _collect_script_writes(path, body, base, doc, sink)
    for match in ARIA_HIDDEN.finditer(text):
        # Hidden from assistive technology, still in the DOM and the page source.
        sink.add(path, doc, match.start(2), len(match.group(2)), "aria_hidden", "aria_hidden_element")
    for match in JSON_LD.finditer(text):
        sink.add(path, doc, match.start(1), len(match.group(1)), "json_ld", "json_ld_block")
    for match in ABS_URL.finditer(text):
        import urllib.parse  # noqa: PLC0415

        url = match.group(1)
        host = urllib.parse.urlparse(url).netloc
        # On a live crawl, a link to the target's own host is not a third
        # party. Labelling it as one would invent findings on every page.
        carrier = "page_link" if target_host and host == target_host else "third_party"
        sink.add(path, doc, match.start(1), len(url), carrier, "absolute_url")
    for match in QUERY_URL.finditer(text):
        sink.add(path, doc, match.start(1), len(match.group(1)), "url", "link_with_query")

    for start, length in _gaps(text, excluded):
        sink.add(path, doc, start, length, "page_text", "text_node")
        chunk = text[start:start + length]
        if "Traceback" in chunk:
            sink.add(path, doc, start, length, "error_surface", "stack_trace")


def _expression_end(body: str, start: int, call: bool) -> int:
    """End of the JS expression starting at start: the closing paren of a call
    (call=True) or the statement end. Quotes and nesting are tracked because a
    value such as "a;b" or f(x, y) must not be cut in the middle.
    """
    depth, quote, escaped = 0, "", False
    for index in range(start, len(body)):
        char = body[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in "\"'`":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return index
            depth -= 1
        elif not call and depth == 0 and char in ";\n":
            return index
    return len(body)


def _collect_script_writes(path: str, body: str, base: int, doc: str, sink: Sink) -> None:
    """One row per storage statement: an IndexedDB write or a cookie assignment.

    A statement is the unit that links a name to a record number, so it is
    kept whole instead of being split per string literal.
    """
    # put/add also name Set.add and similar calls; only a script that opens an
    # IndexedDB database is read for them.
    if "indexedDB" in body:
        for found in IDB_WRITE.finditer(body):
            end = _expression_end(body, found.end(), True)
            sink.add(path, doc, base + found.end(), end - found.end(), "indexeddb", "idb_write")
    for found in COOKIE_SET.finditer(body):
        end = _expression_end(body, found.end(), False)
        sink.add(path, doc, base + found.end(), end - found.end(), "cookie", "cookie_assignment")


def _collect_deploy(path: str, text: str, doc: str, sink: Sink) -> None:
    """Netlify _headers and _redirects: one row per header line or redirect rule.

    A _headers path line only names the route; the indented lines below it are
    the headers that get sent, and a Set-Cookie there is a response leak.
    """
    offset = 0
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        if not body.strip() or body.lstrip().startswith("#"):
            pass
        elif path.endswith("_redirects"):
            sink.add(path, doc, offset, len(body), "response_header", "redirect_rule")
        elif body[0] in " \t":
            sink.add(path, doc, offset, len(body), "response_header", "header_line")
        offset += len(line)


def _collect_js(path: str, text: str, doc: str, sink: Sink) -> None:
    # A file with almost no newlines is a minified bundle. Mark every
    # observation from it, because name detection on mangled code produces
    # nonsense: the first real target yielded "New", "Test" and "rn(n". Bundlers
    # also split code into small chunks (a 7,800-character login view on one
    # line), so size alone does not decide it. Nor do newlines: React's
    # production build has 322 of them, at 409 characters a line. People write
    # lines under about 100 characters; 200 on average is generated code.
    minified = len(text) > 2_000 and len(text) / (text.count("\n") + 1) > 200
    prefix = "minified_" if minified else ""
    sink.add(path, doc, 0, len(text), "js_bundle", f"{prefix}whole_file")
    for match in B64.finditer(text):
        sink.add(path, doc, match.start(), len(match.group(0)), "encoded_value",
                 f"{prefix}base64_like")
    for match in STORAGE.finditer(text):
        sink.add(path, doc, match.start(), len(match.group(0)), "browser_storage",
                 f"{prefix}set_item_call")


def _collect_json(path: str, text: str, doc: str, sink: Sink) -> None:
    if path.endswith(".map"):
        sink.add(path, doc, 0, len(text), "source_map", "whole_file")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None
        for key in ("sourcesContent",):
            for item in (payload or {}).get(key, []) or []:
                if isinstance(item, str):
                    index = text.find(item)
                    if index >= 0:
                        sink.add(path, doc, index, len(item), "source_map", key)
        return
    if "swagger" in path or "openapi" in path:
        carrier = "api_docs"
    elif "/api/" in f"/{path}":
        # Delivery channel wins over format: a FHIR resource served by an API
        # is an API response. Whether to link FHIR resources is decided by
        # content in the detector, not by this label.
        carrier = "api_response"
    elif '"resourceType"' in text:
        carrier = "fhir_resource"
    else:
        carrier = "downloadable_file"
    sink.add(path, doc, 0, len(text), carrier, "whole_file")


def _collect_text(path: str, text: str, doc: str, sink: Sink) -> None:
    # Structured clinical formats are read as fields first. The label is the
    # evidence, so nothing downstream has to guess what a bare number is.
    records = structured.records_for(path, text)
    if records:
        carrier = ("unlinked_file" if "/exports/" in f"/{path}"
                   else "downloadable_file")
        for pairs in records:
            body = structured.render(pairs)
            if not body:
                continue
            derived = sink.vault.put(body.encode("utf-8"))
            sink.add(path, derived, 0, len(body), carrier, "labelled_record",
                     "labelled_record")
        return
    if path.endswith(".log"):
        offset = 0
        for line in text.splitlines(keepends=True):
            body = line.rstrip("\r\n")
            if body:
                sink.add(path, doc, offset, len(body), "log", "log_line")
            offset += len(line)
    elif path.endswith(".env"):
        sink.add(path, doc, 0, len(text), "env_file", "whole_file")
    elif path.endswith(".sql"):
        sink.add(path, doc, 0, len(text), "unlinked_file", "whole_file")
    elif path.endswith(".csv"):
        carrier = "unlinked_file" if "/exports/" in f"/{path}" else "downloadable_file"
        offset = 0
        for line in text.splitlines(keepends=True):
            body = line.rstrip("\r\n")
            if body:
                sink.add(path, doc, offset, len(body), carrier, "csv_row")
            offset += len(line)
    elif path.endswith(".xml"):
        found = False
        for match in LOC.finditer(text):
            sink.add(path, doc, match.start(1), len(match.group(1)), "sitemap", "loc")
            found = True
        if not found:
            sink.add(path, doc, 0, len(text), "downloadable_file", "whole_file")
    elif path.endswith((".hl7", ".x12")):
        # HL7 v2 and X12 are line- or segment-oriented. One segment is one
        # record, so a PID segment keeps its name and its record number together.
        offset = 0
        for line in text.splitlines(keepends=True):
            body = line.rstrip("\r\n")
            if body.strip():
                sink.add(path, doc, offset, len(body), "downloadable_file",
                         "hl7_segment" if path.endswith(".hl7") else "x12_segment")
            offset += len(line)
    elif path.endswith(".css"):
        if PRINT.search(text):
            for match in CSS_CONTENT.finditer(text):
                sink.add(path, doc, match.start(2), len(match.group(2)), "print_css",
                         "print_media_rule")
    elif path.endswith(".svg"):
        for match in SVG_TEXT.finditer(text):
            sink.add(path, doc, match.start(1), len(match.group(1)), "downloadable_file",
                     "svg_text")
    elif "/.git/" in f"/{path}" or path.endswith(".git/config"):
        sink.add(path, doc, 0, len(text), "git_exposure", "whole_file")
    else:
        # Anything readable is worth reading. The first version had no fallback,
        # so thirteen plain-text documents in a real exam were never opened.
        sink.add(path, doc, 0, len(text), "downloadable_file", "whole_file")


def _collect_office(path: str, data: bytes, raw_doc: str, sink: Sink, vault: Vault) -> None:
    """Extract the text from a .docx or .xlsx, which are zip files of XML.

    A word processor file is a container. Reading it as bytes finds nothing; the
    words live inside word/document.xml and xl/sharedStrings.xml.
    """
    import html as html_module  # noqa: PLC0415
    import io  # noqa: PLC0415
    import zipfile  # noqa: PLC0415

    prefixes = ("word/", "xl/") if not path.endswith(".pptx") else ("ppt/",)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            chunks: list[str] = []
            for name in sorted(archive.namelist()):
                if name.startswith(prefixes) and name.endswith(".xml"):
                    markup = archive.read(name).decode("utf-8", "replace")
                    plain = re.sub(r"<[^>]+>", " ", markup)
                    chunks.append(re.sub(r"\s+", " ", html_module.unescape(plain)))
            merged = "\n".join(chunk for chunk in chunks if chunk.strip())
            records = _office_records(archive)
    except Exception:  # noqa: BLE001
        merged, records = "", []

    # Each record is its own derived document: a tracked change or a hidden row
    # is the unit inside which a name and a diagnosis link.
    for carrier, extraction, text in records:
        encoded = text.encode("utf-8")
        sink.add(path, vault.put(encoded), 0, len(encoded), carrier, extraction, extraction)

    if not merged.strip():
        if not records:
            sink.add(path, raw_doc, 0, len(data), "downloadable_file", "binary")
        return
    derived = vault.put(merged.encode("utf-8"))
    sink.add(path, derived, 0, len(merged), "downloadable_file", "office_text", "office_text")


def _xml_text(markup: str, tags: str) -> str:
    """Concatenated text of the named elements (regex alternation), entities decoded."""
    import html as html_module  # noqa: PLC0415

    found = re.findall(rf"<(?:{tags})(?:\s[^>]*)?>(.*?)</(?:{tags})>", markup, re.S)
    return html_module.unescape("".join(found))


def _office_records(archive) -> list[tuple[str, str, str]]:
    """Parts of an OOXML file that the visible text never shows.

    Returns (carrier, extraction, text), one per record, in a stable order.
    """
    import html as html_module  # noqa: PLC0415

    names = set(archive.namelist())

    def read(name: str) -> str:
        return archive.read(name).decode("utf-8", "replace")

    records: list[tuple[str, str, str]] = []
    if "word/document.xml" in names:
        # Document order, so deletions and insertions interleave as written.
        for match in re.finditer(r"<w:(del|ins)\b[^>]*>(.*?)</w:\1>", read("word/document.xml"), re.S):
            text = _xml_text(match.group(2), "w:delText" if match.group(1) == "del" else "w:t")
            if text.strip():
                records.append(("tracked_changes", f"tracked_{match.group(1)}", text))

    if "docProps/core.xml" in names:
        # The properties block is one record, like one JSON object: a creator
        # and a subject in the same file's properties describe the same thing.
        fields = []
        for match in re.finditer(r"<(\w+:\w+)(?:\s[^>]*)?>([^<]+)</\1>", read("docProps/core.xml")):
            value = html_module.unescape(match.group(2)).strip()
            if value:
                fields.append(f"{match.group(1).split(':')[1]}: {value}")
        if fields:
            records.append(("file_metadata", "core_properties", "\n".join(fields)))

    for name in sorted(n for n in names if re.fullmatch(r"ppt/notesSlides/[^/]+\.xml", n)):
        text = _xml_text(read(name), "a:t")
        if text.strip():
            records.append(("speaker_notes", "notes_slide", text))

    if "xl/workbook.xml" in names:
        records += _hidden_sheet_rows(archive, names)
    return records


def _hidden_sheet_rows(archive, names: set[str]) -> list[tuple[str, str, str]]:
    """One record per row of every sheet marked state="hidden".

    The sheet's file is found through the workbook relationships, not by its
    position, because sheet order and file numbering are independent.
    """
    def read(name: str) -> str:
        return archive.read(name).decode("utf-8", "replace") if name in names else ""

    def attributes(tag: str) -> dict[str, str]:
        return dict(re.findall(r'([\w:]+)="([^"]*)"', tag))

    targets = {}
    for rel in re.findall(r"<Relationship\b[^>]*>", read("xl/_rels/workbook.xml.rels")):
        found = attributes(rel)
        targets[found.get("Id")] = found.get("Target", "")
    shared = [_xml_text(si, "t")
              for si in re.findall(r"<si\b[^>]*>(.*?)</si>", read("xl/sharedStrings.xml"), re.S)]

    records: list[tuple[str, str, str]] = []
    for tag in re.findall(r"<sheet\b[^>]*>", read("xl/workbook.xml")):
        found = attributes(tag)
        if found.get("state") != "hidden":
            continue
        target = targets.get(found.get("r:id"), "").lstrip("/")
        sheet = read(target if target.startswith("xl/") else f"xl/{target}")
        for row in re.findall(r"<row\b[^>]*>(.*?)</row>", sheet, re.S):
            cells = []
            for cell, inner in re.findall(r"<c\b([^>]*?)(?:/>|>(.*?)</c>)", row, re.S):
                if 't="s"' in cell:
                    index = _xml_text(inner, "v")
                    text = shared[int(index)] if index.isdigit() and int(index) < len(shared) else ""
                else:
                    text = _xml_text(inner, "t|v")
                if text.strip():
                    cells.append(text)
            if cells:
                records.append(("hidden_sheet", "hidden_row", " ".join(cells)))
    return records


def _collect_image(path: str, data: bytes, raw_doc: str, sink: Sink, vault: Vault) -> None:
    """Pull the printable strings out of an image, where EXIF and XMP live.

    There is no OCR here, so text burned into the pixels is not read and the
    report says so. Metadata is different: PNG text chunks and JPEG APP1 blocks
    routinely carry a patient name, a device and a date.
    """
    # EXIF is read as tagged fields, kept as one record: one image's metadata
    # block, the way one JSON object is one record. Only an image without EXIF
    # falls back to printable strings.
    tags = _exif_tags(data)
    if tags:
        encoded = "\n".join(tags).encode("utf-8")
        sink.add(path, vault.put(encoded), 0, len(encoded), "exif", "exif_block", "exif_block")
        return

    strings: list[str] = []
    run = bytearray()
    for byte in data:
        if 32 <= byte < 127:
            run.append(byte)
        else:
            if len(run) >= 6 and any(chr(b).isalpha() for b in run):
                strings.append(run.decode("ascii"))
            run.clear()
    if len(run) >= 6 and any(chr(b).isalpha() for b in run):
        strings.append(run.decode("ascii"))

    merged = "\n".join(strings[:2000])
    if not merged.strip():
        sink.add(path, raw_doc, 0, len(data), "downloadable_file", "binary")
        return
    derived = vault.put(merged.encode("utf-8"))
    sink.add(path, derived, 0, len(merged), "file_metadata", "image_strings", "image_strings")


_EXIF_NAMES = {0x010E: "ImageDescription", 0x010F: "Make", 0x0110: "Model",
               0x0131: "Software", 0x0132: "DateTime", 0x013B: "Artist",
               0x8298: "Copyright", 0x9286: "UserComment"}


def _exif_tags(data: bytes) -> list[str]:
    """"Name: value" for the text tags in a JPEG's Exif APP1 segment.

    Reads IFD0, and the Exif sub-IFD for UserComment. Any malformed offset ends
    the read with what was found so far; a bad image never stops the scan.
    """
    import struct  # noqa: PLC0415

    if data[:2] != b"\xff\xd8":
        return []
    tiff = b""
    position = 2
    while position + 4 <= len(data) and data[position] == 0xFF:
        marker = data[position + 1]
        size = struct.unpack_from(">H", data, position + 2)[0]
        if marker == 0xE1 and data[position + 4:position + 10] == b"Exif\x00\x00":
            tiff = data[position + 10:position + 2 + size]
            break
        if marker == 0xDA or size < 2:
            break
        position += 2 + size
    if len(tiff) < 8 or tiff[:2] not in (b"II", b"MM"):
        return []

    order = "<" if tiff[:2] == b"II" else ">"
    found: dict[int, str] = {}

    def walk(ifd: int) -> int:
        """Collect text tags of one IFD; return the Exif sub-IFD offset, or 0."""
        sub = 0
        try:
            count = struct.unpack_from(order + "H", tiff, ifd)[0]
            for n in range(count):
                tag, kind, length, field = struct.unpack_from(order + "HHI4s", tiff, ifd + 2 + 12 * n)
                if tag == 0x8769:
                    sub = struct.unpack(order + "I", field)[0]
                if tag not in _EXIF_NAMES or kind not in (2, 7):
                    continue
                start = struct.unpack(order + "I", field)[0] if length > 4 else None
                raw = field[:length] if start is None else tiff[start:start + length]
                if tag == 0x9286:
                    raw = raw[8:]  # 8-byte character-set prefix
                value = raw.split(b"\x00")[0].decode("utf-8", "replace").strip()
                if value:
                    found[tag] = value
        except struct.error:
            pass
        return sub

    try:
        sub = walk(struct.unpack_from(order + "I", tiff, 4)[0])
        if sub:
            walk(sub)
    except struct.error:
        pass
    return [f"{_EXIF_NAMES[tag]}: {found[tag]}" for tag in sorted(found)]


def _collect_dicom(path: str, data: bytes, raw_doc: str, sink: Sink, vault: Vault) -> None:
    """Read the DICOM header and store the tags as a derived text document.

    DICOM is binary, so the bytes are not searchable as text. The header is
    where the identifiers live: patient name, record number, date of birth, the
    ordering physician, and often the diagnosis in StudyDescription. A real
    deployment also has to look at burned-in pixel text; that needs OCR and is
    not attempted here, which is stated rather than implied.
    """
    tags = _dicom_tags(data)
    if not tags:
        sink.add(path, raw_doc, 0, len(data), "downloadable_file", "binary")
        return

    # The tag number is the label. Flattening the header to text loses it.
    records = structured.dicom_records(tags)
    if records and records[0]:
        body = structured.render(records[0])
        if body:
            derived = vault.put(body.encode("utf-8"))
            sink.add(path, derived, 0, len(body), "dicom_header",
                     "labelled_record", "labelled_record")
            return

    lines = [f"{tag}: {value}" for tag, value in tags]
    text = "\n".join(lines)
    derived = vault.put(text.encode("utf-8"))
    # One observation for the whole header, so identity and diagnosis stay in
    # the same record. Per-tag observations would separate the name from the
    # diagnosis and nothing would link.
    sink.add(path, derived, 0, len(text), "dicom_header", "tag_text", "dicom_tags")


def _dicom_tags(data: bytes) -> list[tuple[str, str]]:
    """Minimal reader for explicit-VR little-endian DICOM. No dependencies."""
    import struct  # noqa: PLC0415

    if len(data) < 132 or data[128:132] != b"DICM":
        return []

    long_vr = {b"OB", b"OW", b"OF", b"SQ", b"UT", b"UN"}
    text_vr = {b"PN", b"LO", b"SH", b"DA", b"CS", b"UI", b"ST", b"LT", b"UT",
               b"AE", b"DS", b"IS", b"TM", b"AS", b"FC", b"IT", b"LT"}
    found: list[tuple[str, str]] = []
    position = 132
    while position + 8 <= len(data):
        try:
            group, element = struct.unpack_from("<HH", data, position)
            vr = data[position + 4:position + 6]
            if vr in long_vr:
                length = struct.unpack_from("<I", data, position + 8)[0]
                start = position + 12
            else:
                length = struct.unpack_from("<H", data, position + 6)[0]
                start = position + 8
        except struct.error:
            break
        end = start + length
        if length == 0 or end > len(data):
            position = end
            continue
        if vr in text_vr:
            value = data[start:end].rstrip(b"\x00 ").decode("latin-1", "replace")
            if value:
                found.append((f"{group:04X},{element:04X}", value))
        position = end
    return found


def _collect_pdf(path: str, data: bytes, raw_doc: str, sink: Sink,
                 vault: Vault) -> None:
    sink.add(path, raw_doc, 0, len(data), "downloadable_file", "whole_file_binary")
    try:
        from pypdf import PdfReader  # noqa: PLC0415
    except ImportError:
        return
    import io

    reader = PdfReader(io.BytesIO(data))
    text = "\n".join((page.extract_text() or "") for page in reader.pages)
    if text.strip():
        derived = vault.put(text.encode("utf-8"))
        sink.add(path, derived, 0, len(text), "downloadable_file", "pdf_text_layer", "pdf_text")
    info = reader.metadata or {}
    # Sorted, because dictionary order from the PDF reader is not guaranteed and
    # an unsorted loop made one finding appear and disappear between runs.
    for key, value in sorted(info.items()):
        if isinstance(value, str) and value.strip():
            derived = vault.put(value.encode("utf-8"))
            sink.add(path, derived, 0, len(value), "file_metadata", f"pdf_info{key}", "pdf_metadata")


def collect(source: Path, out: Path, pylibs: str | None = None,
            target_host: str | None = None, key: bytes | None = None) -> dict:
    """Read every file under source into a fresh vault and index under out.

    key: the vault key. Omit it and the scan gets a new random one, which is
    the point of a per-scan key; pass one only to prove determinism.
    """
    if pylibs:
        sys.path.insert(0, pylibs)
    source = Path(source)
    out = Path(out)
    if target_host is None:
        scope = source / "pages" / "scope.json"
        if scope.exists():
            try:
                target_host = json.loads(scope.read_text(encoding="utf-8")).get("target_host")
            except json.JSONDecodeError:
                target_host = None
    if out.exists():
        import shutil
        shutil.rmtree(out)
    vault = Vault(out / "vault", key)
    sink = Sink(vault)

    files = sorted(p for p in source.rglob("*") if p.is_file())
    for path in files:
        rel = path.relative_to(source).as_posix()
        data = path.read_bytes()
        doc = vault.put(data)
        suffix = path.suffix.lower()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = None

        # The filename is a carrier. "Rafael-Ibarra_MRN-881010.html" puts a name
        # and a record number somewhere no body scan will ever look. Only paths
        # that look like they carry one are emitted, to keep the index small.
        posix = rel.replace("\\", "/")
        if re.search(r"[A-Za-z]{3,}[-_][A-Za-z]{3,}|mrn[-_ ]?\d|patient[-_]?id|\d{6,}",
                     posix, re.I):
            path_doc = vault.put(posix.encode("utf-8"))
            sink.add(rel, path_doc, 0, len(posix), "url", "file_path", "file_path")

        if text is not None:
            table = [0]
            for character in text:
                table.append(table[-1] + len(character.encode("utf-8")))
            sink.maps[doc] = table

        if suffix in (".html", ".htm"):
            # CSS can print a patient's name without it ever appearing in the
            # document's text, because the browser generates it.
            for block in re.finditer(r"(?is)<style\b[^>]*>(.*?)</style>", text):
                for match in CSS_CONTENT.finditer(block.group(1)):
                    sink.add(rel, doc, block.start(1) + match.start(2), len(match.group(2)),
                             "css_hidden", "style_block")

        if suffix == ".pdf":
            _collect_pdf(rel, data, doc, sink, vault)
        elif suffix == ".dcm":
            _collect_dicom(rel, data, doc, sink, vault)
        elif suffix in (".docx", ".xlsx", ".pptx"):
            _collect_office(rel, data, doc, sink, vault)
        elif suffix in (".png", ".jpg", ".jpeg", ".gif", ".tif", ".tiff"):
            _collect_image(rel, data, doc, sink, vault)
        elif text is None:
            sink.add(rel, doc, 0, len(data), "downloadable_file", "binary")
        elif path.name in ("_headers", "_redirects"):
            _collect_deploy(rel, text, doc, sink)
        elif path.name.lower() == "robots.txt":
            offset = 0
            for line in text.splitlines(keepends=True):
                body = line.rstrip("\r\n")
                if body and not body.lstrip().startswith("#"):
                    sink.add(rel, doc, offset, len(body), "robots_txt", "robots_line")
                offset += len(line)
        elif suffix in (".html", ".htm"):
            _collect_html(rel, text, doc, sink, target_host)
        elif suffix == ".js":
            _collect_js(rel, text, doc, sink)
        elif suffix in (".json", ".map"):
            _collect_json(rel, text, doc, sink)
        else:
            _collect_text(rel, text, doc, sink)

    rows = sorted(sink.rows, key=lambda r: (r["path"], r["offset"], r["carrier"], r["extraction"]))
    for index, row in enumerate(rows, start=1):
        row["obs_id"] = f"o{index:06d}"

    index_path = out / "index.jsonl"
    with index_path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    carriers: dict[str, int] = {}
    for row in rows:
        carriers[row["carrier"]] = carriers.get(row["carrier"], 0) + 1

    index_bytes = index_path.read_bytes()
    manifest = {
        "version": 1,
        "source_files": len(files),
        "observations": len(rows),
        "carriers": dict(sorted(carriers.items())),
        "grades": {"B": len(rows)},
        "vault": {"objects_written": vault.written, "objects_reused": vault.reused},
        "index_sha256": hashlib.sha256(index_bytes).hexdigest(),
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest
