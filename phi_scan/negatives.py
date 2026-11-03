"""The eight do-not-flag predicates (policy/negatives.yaml, spec 2.5).

Each function answers one question about one record: is there evidence that
this is not an exposure? It returns that evidence as a short sentence, or None.
Returning the reason rather than a bool is the point: a finding that was
cleared says why, so a reviewer can disagree with the reason instead of
wondering where a finding went.

None of these can clear an always-flag identifier (SSN, MRN, plan id). The
detector enforces that; these functions do not need to know it.
"""

from __future__ import annotations

import html
import ipaddress
import re
from dataclasses import dataclass, field

from .validators import npi_valid

SMALL_CELL = 11

STAFF_DIRS = re.compile(r"(?:^|/)(?:doctors?|providers?|staff|team|physicians|clinicians|our-team)(?:/|\.|$)", re.I)
PHYSICIAN_MARKUP = re.compile(r"""(?:"@type"\s*:\s*"Physician"|schema\.org/Physician)""")
PROVIDER_TITLE = re.compile(r"\b(?:Dr\.?|MD|DO|NP|PA-C|RN|DDS|PhD)\b")
NPI = re.compile(r"\b(\d{10})\b")
PATIENT_CUE = re.compile(
    r"\b(?:patient|diagnosed|presents? with|admitted|discharged|my (?:diagnosis|treatment|"
    r"surgery|doctor)|was treated|is being treated|testimonial|her story|his story|"
    r"their story|living with|survivor|undergoing|prescribed|on \w+ therapy)\b", re.I)
BYLINE = re.compile(r"\b(?:written by|reviewed by|by|author|medically reviewed by)\s*:?\s*$", re.I)
GROUP_COUNT = re.compile(
    r"(\d[\d,]*)\s+(?:of\s+\w+\s+)?(?:patients|adults|people|children|members|cases|"
    r"residents|participants|women|men|veterans|individuals|visits|screened)", re.I)
CONTACT_PATH = re.compile(r"(?:^|/)(?:contact|about|locations?|index)(?:\.html?|/|$)", re.I)
ORG_WORD = re.compile(r"\b(?:Health|Clinic|Hospital|Partners|Medical|Center|Centre|Care|Group|Associates)\b")
ROLE_MAILBOX = re.compile(r"\b(?:info|contact|hello|appointments|billing|support|admin|office)@", re.I)
CODE = re.compile(
    r"\b(?:[A-TV-Z]\d{2}(?:\.\d{1,4}[A-Z]?)?|\d{5}|\d{1,5}-\d)\b")  # ICD-10, CPT, LOINC
CONSENT = re.compile(
    r"\b(?:with (?:the )?(?:\w+'s |person's |patient's |their |his |her )?(?:written |express |"
    r"full |signed )?(?:consent|permission)|used with permission|consented to (?:share|publish|"
    r"this)|names? (?:and (?:identifying )?details )?(?:have been |has been |were )?changed|"
    r"dramati[sz]ation|fictional|composite (?:character|story))",
    re.I)
# A structured testimonial states consent as a field, not a sentence.
CONSENT_FIELD = re.compile(
    r'"consent(?:_given|ed|_status)?"\s*:\s*(?:true|"(?:yes|given|written|signed|granted|'
    r'obtained|on file)[^"]*")', re.I)
BLOCK_OPEN = re.compile(r"<(p|li|blockquote|td|tr|dl|dd|figcaption|figure|address|div|section|"
                        r"article|footer)\b[^>]*>", re.I)
# The elements that are one record: a consent note in a sibling cell of the same
# row, in the caption of the same figure, or in another field of the same
# definition list, belongs to that record.
RECORD_TAGS = {"p", "li", "blockquote", "td", "tr", "dl", "dd", "figcaption", "figure", "article"}
# A block this short that is mostly a consent marker annotates the record next
# to it, before or after ("<p><strong>Shared with permission</strong></p>").
NOTE_MAX = 80
ORG_SCHEMA = re.compile(
    r'"@type"\s*:\s*"(?:Organization|MedicalOrganization|Hospital|MedicalClinic|LocalBusiness|'
    r'Pharmacy|DiagnosticLab|MedicalBusiness|NGO|Corporation)"')
TAG = re.compile(r"<[^>]+>")
IMG_ALT = re.compile(r"""<img\b[^>]*\balt\s*=\s*["']([^"']*)["'][^>]*>""", re.I)
WHITESPACE = re.compile(r"\s+")
RESERVED_DOMAINS = (".example", ".test", ".invalid", ".localhost",
                    "example.com", "example.net", "example.org")
RESERVED_NETS = [ipaddress.ip_network(n) for n in
                 ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


@dataclass
class Record:
    """One structural record and what the detector already knows about it."""
    text: str
    page: str = ""
    path: str = ""
    names: list[str] = field(default_factory=list)
    health: bool = False
    direct_ids: list[str] = field(default_factory=list)   # values of non-name identifiers
    own_values: set[str] = field(default_factory=set)     # the scanning account's own record


def provider_staff_page(record: Record) -> str | None:
    if PATIENT_CUE.search(record.text):
        return None
    if STAFF_DIRS.search(record.path):
        return f"staff directory path {record.path}"
    if PHYSICIAN_MARKUP.search(record.page):
        return "schema.org Physician markup on the page"
    # The NPI may sit in the next cell of the same table row: read the record
    # elements that hold this text, not just the text run.
    for text in [record.text] + [t for tag, t, _ in containing_blocks(record) if tag in RECORD_TAGS]:
        if PATIENT_CUE.search(text):
            return None
        if any(npi_valid(n) for n in NPI.findall(text)) and PROVIDER_TITLE.search(text):
            return "a valid NPI next to a clinician's title"
    return None


def public_health_article(record: Record) -> str | None:
    if not record.names or PATIENT_CUE.search(record.text):
        return None
    # Only a byline is evidence. "A health topic with no patient cue" is not:
    # most real leaks name a person and a condition with no cue word at all.
    for name in record.names:
        before = record.text[:max(record.text.find(name), 0)]
        if BYLINE.search(before[-40:]):
            return "the named person is the article's byline, not a patient"
    return None


def group_statistics(record: Record) -> str | None:
    counts = [int(m.group(1).replace(",", "")) for m in GROUP_COUNT.finditer(record.text)]
    if not counts or record.direct_ids or record.names:
        return None
    if min(counts) >= SMALL_CELL:
        return f"counts describe groups of {min(counts)} or more"
    return None


def small_cell(record: Record) -> bool:
    """A group count under the threshold: a review item, not a clean record."""
    counts = [int(m.group(1).replace(",", "")) for m in GROUP_COUNT.finditer(record.text)]
    return bool(counts) and min(counts) < SMALL_CELL


def reserved_value(kind: str, value: str) -> str | None:
    """Values set aside for testing and documentation (spec 2.5, M3 decision)."""
    digits = re.sub(r"\D", "", value)
    if kind == "ssn" and len(digits) == 9:
        area, group, serial = digits[:3], digits[3:5], digits[5:]
        if area in ("000", "666") or group == "00" or serial == "0000":
            return "SSA never issues this SSN"
        if digits[:5] == "98765" and 4320 <= int(serial) <= 4329:
            return "the SSA advertising block"
    if kind in ("phone", "fax") and len(digits) >= 7 and digits[-7:-4] == "555" \
            and 100 <= int(digits[-4:]) <= 199:
        return "555-0100 to 555-0199 is reserved for fiction"
    if kind == "email" and value.lower().rstrip(".").endswith(RESERVED_DOMAINS):
        return "an RFC 2606 reserved domain"
    if kind == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
        if any(address in net for net in RESERVED_NETS):
            return "an RFC 5737 / 3849 documentation address"
    return None


def reserved_synthetic_value(record: Record, kind: str = "", value: str = "") -> str | None:
    return reserved_value(kind, value) if kind and value else None


def company_contact(record: Record) -> str | None:
    if record.health and record.names:
        return None
    footer = "<footer" in record.page.lower() and record.text in record.page.split("<footer", 1)[-1]
    if (footer or CONTACT_PATH.search(record.path)) and ORG_WORD.search(record.text) \
            and (ROLE_MAILBOX.search(record.text) or not record.names):
        return "the organisation's own contact block"
    if ORG_SCHEMA.search(record.text):
        return "schema.org markup describing an organisation"
    if any(tag == "address" for tag, _, _ in containing_blocks(record)) and not record.names:
        return "an <address> block with no person in it"
    if ORG_WORD.search(record.text) and ROLE_MAILBOX.search(record.text) and not record.names:
        return "an organisation's name beside its role mailbox"
    return None


def code_reference(record: Record) -> str | None:
    if record.names or record.direct_ids:
        return None
    if CODE.search(record.text):
        return "codes and their descriptions, with no person attached"
    return None


def own_record(record: Record) -> str | None:
    values = set(record.names) | set(record.direct_ids)
    if values and record.own_values and values <= record.own_values:
        return "the scanning account's own record"
    return None


def _plain(markup: str) -> str:
    # Image alt text is part of the record, as it is in the rendered text.
    markup = IMG_ALT.sub(lambda m: f" {m.group(1)} ", markup)
    return WHITESPACE.sub(" ", html.unescape(TAG.sub(" ", markup))).strip()


def _needle(record: Record) -> str:
    """The record's text as page blocks spell it. The renderer joins a record's
    blocks with " | " ("Priya Nair | her story"); the page has no pipes, so a
    multi-block record never found its own element or the note beside it."""
    return WHITESPACE.sub(" ", record.text.replace("|", " ")).strip()


def containing_blocks(record: Record) -> list[tuple[str, str, str]]:
    """(tag, text, note) for every block element on the page that holds the
    record, nested ones included. Text extraction splits at every tag, so a
    consent note in an <em>, or in the next cell of the same table row, arrives
    as a separate run; the record is the paragraph or the row, not the run.

    note is the short text right after the element closes, before the next
    block starts: a "<small>Fictional account</small>" under a figure is the
    figure's caption in all but markup."""
    needle = _needle(record)
    found = []
    if not needle:
        return found
    for opening in BLOCK_OPEN.finditer(record.page):
        tag = opening.group(1).lower()
        closing = re.compile(rf"</{tag}\s*>", re.I).search(record.page, opening.end())
        if closing is None:
            continue
        text = _plain(record.page[opening.end():closing.start()])
        if needle in text:
            following = record.page[closing.end():closing.end() + 400]
            next_block = BLOCK_OPEN.search(following)
            note = _plain(following[:next_block.start()] if next_block else following)[:120]
            found.append((tag, text, note))
    return found


def consented_testimonial(record: Record) -> str | None:
    field = CONSENT_FIELD.search(record.text)
    if field:
        return f"a consent field in the record: {field.group(0)}"
    for tag, text, note in [("record", record.text, "")] + containing_blocks(record):
        if tag not in RECORD_TAGS and tag != "record":
            continue
        match = CONSENT.search(text) or CONSENT.search(note)
        if match:
            return f'a visible consent marker: "{match.group(0)}"'
    for note in adjacent_notes(record):
        match = CONSENT.search(note)
        if match and len(match.group(0)) >= len(note) / 2:
            return f'a consent note beside the record: "{match.group(0)}"'
    return None


def adjacent_notes(record: Record) -> list[str]:
    """The short blocks immediately before and after the record's innermost
    record element: where a page puts a one-line note about one story."""
    needle = _needle(record)
    # The innermost element holding the whole record, whatever its tag: a card
    # is a <div>, and the note sits beside the card.
    best = None
    for opening in BLOCK_OPEN.finditer(record.page):
        tag = opening.group(1).lower()
        closing = re.compile(rf"</{tag}\s*>", re.I).search(record.page, opening.end())
        if closing and needle and needle in _plain(record.page[opening.end():closing.start()]) \
                and (best is None or closing.end() - opening.start() < best[1] - best[0]):
            best = (opening.start(), closing.end())
    if best is None:
        return []
    before = [m for m in BLOCK_OPEN.finditer(record.page, 0, best[0])]
    notes = []
    if before:
        tag = before[-1].group(1).lower()
        end = re.compile(rf"</{tag}\s*>", re.I).search(record.page, before[-1].end())
        # A note between two stories belongs to the one before it, so a note
        # counts for the record after it only when no story precedes the note.
        story_before_note = False
        if len(before) > 1:
            prior = before[-2]
            prior_end = re.compile(rf"</{prior.group(1)}\s*>", re.I).search(record.page, prior.end())
            story_before_note = bool(prior_end) and prior.group(1).lower() in RECORD_TAGS and \
                len(_plain(record.page[prior.end():prior_end.start()])) >= 20
        if end and end.end() <= best[0] and not story_before_note:
            notes.append(_plain(record.page[before[-1].end():end.start()]))
    # Inline text right after the element ("</div><small>Names changed</small>"),
    # then the next block.
    following = record.page[best[1]:best[1] + 400]
    next_block = BLOCK_OPEN.search(following)
    notes.append(_plain(following[:next_block.start()] if next_block else following))
    after = BLOCK_OPEN.search(record.page, best[1])
    if after:
        tag = after.group(1).lower()
        end = re.compile(rf"</{tag}\s*>", re.I).search(record.page, after.end())
        if end:
            notes.append(_plain(record.page[after.end():end.start()]))
    return [note for note in notes if 0 < len(note) <= NOTE_MAX]


PREDICATES = {
    "provider_staff_page": provider_staff_page,
    "public_health_article": public_health_article,
    "group_statistics": group_statistics,
    "reserved_synthetic_value": reserved_synthetic_value,
    "company_contact": company_contact,
    "code_reference": code_reference,
    "own_record": own_record,
    "consented_testimonial": consented_testimonial,
}
