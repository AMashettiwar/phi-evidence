"""Decide what is a finding.

The detector reads evidence observations and decides, by rule, whether a record
contains something that identifies a person together with something about their
health. It never writes a patient value into its output: findings carry a
masked form and a hash, and the evidence pointer they came from.

What it does not do: judge severity perfectly, or decide whether a leak is real
in the legal sense. Severity here is provisional and gets its own gate.

Three rules that took a failing gate to learn:
  * A name with an apostrophe ("Priya O'Rourke") is still a name. The first
    version of the name pattern silently skipped every one.
  * A phone number or an email on its own is not a person. Linking identity to
    health needs a name, a record number, or a Social Security number, or the
    organisation's own switchboard number gets reported as a patient.
  * The same leak often arrives under two labels (page text and hidden code,
    inline script and browser storage). One finding per file per value, keeping
    the more specific label, or the report double-counts and precision collapses.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import urllib.parse
from pathlib import Path

from .clinical import health
from .negatives import PREDICATES, Record
from .normalize import normalize
from .validators import mbi_valid
from .lexicon import NAME_STOP, suppression_reason
from .severity import HIGH_CARRIERS, WITHHOLD_CARRIERS, audience, decide

# Labels that mean "definitely not a person". Used to veto regex candidates:
# this is what removes "Northern Ireland", "Royal Navy" and "European Commission"
# without adding a single stop-list word.
NON_PERSON_LABELS = {"ORG", "GPE", "LOC", "FAC", "NORP"}

# An ORG label is only trusted when the entity actually looks organised. The
# small model labels plain two-word names as ORG ("Ingrid Vasquez"), and
# trusting that erased a real patient.
ORG_KEYWORDS = (
    "court", "commission", "navy", "ministry", "university", "college",
    "council", "department", "agency", "office", "board", "inc", "ltd",
    "llc", "association", "society", "institute", "authority", "committee",
    "parliament", "government", "company", "corp", "group", "hospital",
    "clinic", "center", "centre", "school", "bank", "fund", "union",
    "party", "army", "police", "service", "bureau", "assembly",
)

_NLP = None
# The scan's vault key, set by detect(); digest() tokenises values with it.
_TOKEN_KEY = b""
# Record-number shapes learned from this scan's labelled ids, set by detect().
_SHAPES: list[re.Pattern] = []
_NLP_LOADED = False

# The model dominates the runtime, and the same strings recur constantly across
# a site (navigation, footers, identical rows). A bounded cache is the cheapest
# large win; it changes no result, only how often the model is asked.
_NAME_CACHE: dict[str, list[tuple[int, int, str]]] = {}
_NAME_CACHE_MAX = 20000


def _load_model():
    """Load the NER model once. A missing model is an error, not a fallback.

    A silent fallback to regex names changed the results without saying so: the
    same commit passed in one environment and failed in CI. The model name is
    configurable so that two models can be compared with the same code.
    """
    global _NLP, _NLP_LOADED
    if _NLP_LOADED:
        return _NLP
    import os  # noqa: PLC0415

    import spacy  # noqa: PLC0415

    _NLP = spacy.load(os.environ.get("PHI_SCAN_MODEL", "en_core_web_sm"))
    _NLP_LOADED = True
    return _NLP


def _mostly_inside(start: int, end: int, ranges: list[tuple[int, int]],
                   threshold: float = 0.6) -> bool:
    """True when one of these ranges covers most of the span.

    A place or organisation label on part of a name must not veto the whole
    name. spaCy labels "Delgado" as a GPE inside "Emeka Delgado", and a plain
    overlap test lost nine planted leaks before this threshold existed.
    """
    width = max(1, end - start)
    for lo, hi in ranges:
        overlap = min(end, hi) - max(start, lo)
        if overlap > 0 and overlap / width >= threshold:
            return True
    return False
from .vault import Vault

# A separator between name parts, allowing zero-width characters and
# non-breaking spaces: "Emeka\u200b Delgado" is still one person and a plain
# \s+ misses it entirely.
SEP = r"[\s\u200b\u200c\u200d\u2060\ufeff]+"
# "MRN-881781", "MRN: 00901453", "MR# 1234567", "Medical Record #: 2299586".
MRN = re.compile(r"(?<![A-Za-z0-9])(?:MRN[-\s:#]*|MR#\s*|Medical\s+Record\s*(?:#|No\.?|Number)?"
                 r"\s*[:#]?\s*)\d{3}[\s-]?\d{3,}\b", re.I)
# Medicare Beneficiary Identifier, by CMS position rules; validated, and only
# beside a label, because an unlabelled 11-character code is often a product code.
MBI = re.compile(r"\b[1-9][AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d-?[AC-HJKMNP-RT-Y]"
                 r"[AC-HJKMNP-RT-Y0-9]\d-?[AC-HJKMNP-RT-Y]{2}\d{2}\b")
MBI_LABEL = re.compile(r"(?:MBI|medicare|member[\s_-]*(?:id|no|number)?|beneficiary)\W{0,6}$", re.I)
SSN = re.compile(r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b")
DOB = re.compile(r"\b(?:19|20)\d{2}-\d{2}-\d{2}\b")
# Real records write dates in every shape there is. A detector that only knows
# ISO 8601 misses most of them.
DATE_US = re.compile(r"\b(?:0?[1-9]|1[0-2])/(?:0?[1-9]|[12]\d|3[01])/(?:\d{4}|\d{2})\b")
DATE_MONTH = re.compile(
    r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+"
    r"\d{1,2},?\s+(?:19|20)\d{2}\b", re.I)
DATE_COMPACT = re.compile(r"\b(?:19|20)\d{6}\b")
# A bare 6-8 digit run is a record number when the same record names a person.
# Ten digits is an NPI and five is a LOINC code, so both stay out.
BARE_ID = re.compile(r"(?<![\d-])\d{6,8}(?![\d-])")
# "DULUTH, MN 55803": a ZIP follows a two-letter state.
ZIP_CODE = re.compile(r"\b[A-Z]{2}\s+(\d{5})\b")
PHONE = re.compile(
    # (218) 555-0147, 218-555-0147, 713.555.0164, +1(207)555-0119, 218^5550147
    r"(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]\d{4}\b"
    r"|\b\d{3}\^\d{7}\b")
DATETIME = re.compile(
    r"\b(?:19|20)\d{2}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?"
    r"(?:[+-]\d{2}:?\d{2}|Z)?\b")
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
IPV4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
# A word: a letter of any script, then letters, digits, apostrophes or hyphens.
# Capitalisation is enforced in code with str.isupper(), not in the regex, so
# that "İbrahim" and "Güzeler" count as capitalised and "turkey" does not.
# An apostrophe is only part of a word when a letter follows it, so a closing
# quote is never absorbed: 'Rahimi' must not become "Rahimi'".
# No underscore: "DEMO_PATIENT_MRN" is a code identifier, and admitting it let
# "Bhatt DEMO_PATIENT_MRN" outgrow "Freya Bhatt" on an .env line.
WORD = r"[^\W\d_](?:[^\W_]|-|'(?=[^\W\d_]))*"
TITLE_WORD = rf"{WORD}\.?"
# A lookahead, so every adjacent pair is considered. A consuming pattern eats
# the second word of a rejected pair: in "for Emeka Delgado", ("for","Emeka")
# fails the stop list and takes "Emeka" with it, so the real name is never seen.
# This cost two planted leaks and a regression at gate G5 before it was spotted.
NAME = re.compile(rf"(?=\b({WORD}){SEP}({WORD})\b)")
NAME_COMMA = re.compile(rf"\b({WORD}),{SEP}({WORD})\b")
# A name introduced by its own label needs only one word: "patient: Zozo".
LABELED_NAME = re.compile(
    r"\b(?:patient|member|subscriber|guarantor|relative|contact|next of kin|"
    r"provider|physician|surgeon|pathologist|name)\s*[:=]\s*"
    r"([A-Z][a-zA-Z'.-]{2,})", re.I)
# Clinical acronyms. A two-word all-caps span is a name unless one of these.
ACRONYMS = {
    "HIV", "AIDS", "MRSA", "COVID", "SARS", "CPR", "ICU", "ER", "OR", "CT",
    "MRI", "EKG", "ECG", "CBC", "BMP", "CMP", "TSH", "HPV", "STD", "STI",
    "TB", "UTI", "CKD", "ESRD", "COPD", "CHF", "MI", "CVA", "DVT", "PE",
    "GI", "GU", "CNS", "WBC", "RBC", "HGB", "PO", "IV", "IM", "PRN", "BID",
    "TID", "QID", "NPO", "DNR", "BMI", "BP", "HR", "RR", "O2", "DNA", "RNA",
}
# Real prose names people with an honourific: "Mr Galip Yalman". Anchoring on
# that is far more precise than capitalisation alone, and it recovers the name
# when the surname follows a title the stop list would otherwise eat.
TITLE = re.compile(
    r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Sir|Dame)\.?" + SEP +
    rf"({TITLE_WORD}(?:{SEP}{TITLE_WORD}){{0,2}})",
)
B64 = re.compile(r"^[A-Za-z0-9+/]{24,}={0,2}$")

PRIVATE_IP = ("10.", "127.", "192.168.", "172.16.", "0.0.0.0")
TEST_IP = ("192.0.2.", "198.51.100.", "203.0.113.")

# Carrier classes and severity live in severity.py, so there is one place to
# change the ladder and one place to test it.

# When the same value appears under two labels, keep the more specific one.
CARRIER_RANK = {"page_text": 0, "inline_script": 1, "downloadable_file": 2}
DEFAULT_RANK = 5


def rank(carrier: str) -> int:
    return CARRIER_RANK.get(carrier, DEFAULT_RANK)


def mask(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]


def digest(value: str) -> str:
    """The HMAC token of a value under the current scan's vault key.

    detect() sets the key. A plain SHA-256 of an SSN is reversible by trying
    every SSN, so nothing written to a finding is an unkeyed hash of a value.
    """
    return hmac.new(_TOKEN_KEY, b"value\0" + value.encode("utf-8"), hashlib.sha256).hexdigest()


def ssn_valid(value: str) -> bool:
    parts = [part for part in re.split(r"[-\s]+", value) if part]
    if len(parts) != 3:
        return False
    area, group, serial = parts
    if area in ("000", "666") or area.startswith("9"):
        return False
    if group == "00" or serial == "0000":
        return False
    return True


# English abstract nouns end like this. A surname almost never does, so a
# capitalised pair whose last word is "Collection" or "Documentation" is a field
# label in a structured API, not a person.
ABSTRACT_SUFFIXES = ("tion", "sion", "ment", "ity", "ness", "ous", "ence", "ance")


def _abstract_noun(token: str) -> bool:
    lowered = token.lower()
    return any(lowered.endswith(suffix) for suffix in ABSTRACT_SUFFIXES)


# A place or nationality label is only trusted when the words are actually
# places. The small model called "Marisol Lindqvist" a place, and the veto
# deleted a real patient with it.
PLACE_WORDS = {
    "ireland", "britain", "england", "scotland", "wales", "kingdom", "france",
    "germany", "spain", "italy", "greece", "turkey", "russia", "ukraine",
    "china", "japan", "india", "pakistan", "bangladesh", "nigeria", "kenya",
    "ghana", "egypt", "morocco", "brazil", "mexico", "canada", "america",
    "states", "europe", "asia", "africa", "australia", "zealand", "london",
    "paris", "berlin", "madrid", "rome", "moscow", "ankara", "istanbul",
    "izmir", "delhi", "mumbai", "beijing", "tokyo", "cairo", "nairobi",
    "dublin", "edinburgh", "cardiff", "belfast", "siverek", "hilvan",
    "edirne", "diyarbakir", "portugal", "netherlands", "belgium", "sweden",
    "norway", "denmark", "finland", "poland", "austria", "switzerland",
    "hungary", "romania", "bulgaria", "serbia", "croatia", "albania",
    "northern", "southern", "eastern", "western", "republic", "island",
    "city", "county", "province", "region", "district",
}


def _clean_name(name: str) -> str:
    """Remove characters that are invisible on screen but break matching."""
    for invisible in ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"):
        name = name.replace(invisible, "")
    return re.sub(r"\s+", " ", name).strip()


MAX_NER_CHARS = 40000


def _windows(text: str, size: int):
    """Split long text into model-sized windows, preferring whitespace breaks."""
    if len(text) <= size:
        yield 0, text
        return
    start = 0
    while start < len(text):
        end = min(start + size, len(text))
        if end < len(text):
            cut = text.rfind(" ", end - 500, end)
            if cut > start:
                end = cut
        yield start, text[start:end]
        start = end


def _model_entities(text: str) -> tuple[list[tuple[int, int, int, str]],
                                        list[tuple[int, int]]]:
    """PERSON candidates and non-person vetoes from the model, over any length.

    spaCy refuses text over its own limit, and a minified JavaScript bundle is
    one and a half million characters. Chunking keeps a real scan from crashing
    on the first large file it meets.
    """
    persons: list[tuple[int, int, int, str]] = []
    blocked: list[tuple[int, int]] = []
    nlp = _load_model()
    for offset, chunk in _windows(text, MAX_NER_CHARS):
        try:
            doc = nlp(chunk)
        except Exception:  # noqa: BLE001
            continue
        for entity in doc.ents:
            start = offset + entity.start_char
            end = offset + entity.end_char
            if entity.label_ == "PERSON":
                # The model absorbs closing quotes and punctuation into the
                # span: 'Yuki Rahimi' comes back as "Yuki Rahimi'". Trim it, or
                # the name is stored with a trailing quote and never matches.
                while start < end and not text[start].isalnum():
                    start += 1
                while end > start and not text[end - 1].isalnum():
                    end -= 1
                name = _clean_name(text[start:end])
                # A single token is a code keyword or a label far more often
                # than it is a person: "Model", "Return", "JSON" all qualified.
                if " " not in name:
                    continue
                # "B20" is a diagnosis code, not a person.
                if len(name) < 3 or any(char.isdigit() for char in name):
                    continue
                # The stop list applies to the model too. It did not before, and
                # that is why "Lung" and "Bladder" survived as patient names.
                tokens = [token.strip(".,'-").lower() for token in name.split()]
                if any(token in NAME_STOP for token in tokens):
                    continue
                if _abstract_noun(tokens[-1]):
                    continue
                persons.append((0, start, end, name))
            elif entity.label_ in NON_PERSON_LABELS:
                if entity.label_ == "ORG":
                    lowered = entity.text.lower()
                    # Count only real words. An HTML entity beside a name must
                    # not turn a two-word person into a three-word company —
                    # that is exactly what hid "Marisol Lindqvist &mdash;".
                    words = [word for word in entity.text.split()
                             if any(char.isalpha() for char in word)
                             and not word.startswith("&")]
                    organised = (
                        len(words) >= 3
                        or lowered.startswith(("the ", "a ", "an "))
                        or any(word in lowered for word in ORG_KEYWORDS)
                    )
                    if not organised:
                        continue
                else:
                    words = {word.strip(".,'-").lower() for word in entity.text.split()}
                    if not (words & PLACE_WORDS):
                        continue
                blocked.append((start, end))
    return persons, blocked


def name_spans(text: str) -> list[tuple[int, int, str]]:
    """Every person-name span, with offsets.

    Two passes. The first anchors on an honourific, which is how most real
    people are named in prose and is much more precise than capitalisation.
    The second catches bare "First Last" pairs, skipping anything the first
    pass already claimed and anything in the stop list.

    Both the detector and the evaluation import this, so the thing being
    measured is the thing that runs.
    """
    # A name needs a capital letter. Most spans on a real site have none, and
    # skipping the model for those is free.
    if len(text) < 3 or not any(character.isupper() for character in text):
        return []
    cached = _NAME_CACHE.get(text)
    if cached is not None:
        return cached

    # priority, start, end, text. Lower priority wins an overlap: the model (0)
    # beats an honourific match (1), which beats a bare capitalised pair (2).
    # Longest-wins was wrong: it preferred "Bhatt DEMO_PATIENT_MRN" over the
    # model's "Freya Bhatt" simply because it was longer.
    candidates: list[tuple[int, int, int, str]] = []
    blocked: list[tuple[int, int]] = []

    # The model is the primary opinion, but not the only one: it splits
    # "Desmond Ferreira" into a person plus a place, and misses initials.
    model_persons, model_blocked = _model_entities(text)
    candidates.extend(model_persons)
    blocked.extend(model_blocked)

    for match in TITLE.finditer(text):
        kept: list[str] = []
        for word in match.group(1).split():
            # Stop at the first word that is not capitalised: "Mr Smith said"
            # must yield "Smith", not "Smith said".
            if not word[0].isupper():
                break
            if word.rstrip(".").lower() in NAME_STOP:
                break
            kept.append(word)
        if not kept:
            continue
        start = match.start(1)
        candidates.append((1, start, start + len(" ".join(kept)), " ".join(kept)))

    for match in NAME.finditer(text):
        start, end = match.start(1), match.end(2)
        first, last = match.group(1), match.group(2)
        if not first[0].isupper() or not last[0].isupper():
            continue
        if first.lower() in NAME_STOP or last.lower() in NAME_STOP:
            continue
        # A single letter is an initial, not a name, unless an honourific
        # anchored it in the first pass.
        if len(first.rstrip(".")) < 2 or len(last.rstrip(".")) < 2:
            continue
        # "HIV POSITIVE" is an acronym pair, not a person. Only reject pairs
        # that actually look like clinical acronyms — "SMITH JOHN" is a name
        # written the way a lab system writes it.
        if first.isupper() and last.isupper():
            if (first.rstrip(".") in ACRONYMS or last.rstrip(".") in ACRONYMS
                    or (len(first) <= 3 and len(last) <= 3)):
                continue
        # "B20" and "MRN" are codes, not people.
        if any(char.isdigit() for char in first + last):
            continue
        # "Sample Collection" is a field label, not a person.
        if _abstract_noun(last):
            continue
        prefix = text[max(0, start - 5):start].strip()
        if prefix.endswith("Dr."):
            continue
        candidates.append((2, start, end, f"{first} {last}"))

    # "SMITH, JANE" is the same person as "Jane Smith". Two letters are
    # rejected so a city/state pair ("Bangor, ME") is never read as a name.
    for match in NAME_COMMA.finditer(text):
        start, end = match.start(1), match.end(2)
        last, first = match.group(1), match.group(2)
        if not last[0].isupper() or not first[0].isupper():
            continue
        if len(first) < 3 or len(last) < 2:
            continue
        if last.lower() in NAME_STOP or first.lower() in NAME_STOP:
            continue
        if _abstract_noun(first) or any(ch.isdigit() for ch in last + first):
            continue
        candidates.append((2, start, end, f"{first} {last}"))

    for match in LABELED_NAME.finditer(text):
        name = _clean_name(match.group(1))
        if len(name) < 3 or name.lower() in NAME_STOP:
            continue
        start = match.start(1)
        candidates.append((2, start, start + len(match.group(1)), name))

    # Drop anything the model says is an organisation or a place.
    surviving = [c for c in candidates if not _mostly_inside(c[1], c[2], blocked)]

    # Keep the longest of any overlapping candidates, so "Desmond" does not
    # beat "Desmond Ferreira" and nothing is reported twice.
    surviving.sort(key=lambda c: (c[1], c[0], -(c[2] - c[1])))
    merged: list[tuple[int, int, int, str]] = []
    for candidate in surviving:
        if merged and candidate[1] < merged[-1][2]:
            previous = merged[-1]
            cand_contains = candidate[1] <= previous[1] and candidate[2] >= previous[2]
            prev_contains = previous[1] <= candidate[1] and previous[2] >= candidate[2]
            if cand_contains and not prev_contains:
                # A span that contains the other wins. The model often returns
                # only the first name ("Desmond") where the pair is clearly
                # "Desmond Ferreira", and priority alone would keep the stump.
                better = True
            elif prev_contains and not cand_contains:
                better = False
            else:
                # Partial overlap: trust the better source, then the longer one.
                better = candidate[0] < previous[0] or (
                    candidate[0] == previous[0]
                    and (candidate[2] - candidate[1]) > (previous[2] - previous[1])
                )
            if better:
                merged[-1] = candidate
            continue
        merged.append(candidate)

    result = [(start, end, name) for _, start, end, name in merged]
    if len(_NAME_CACHE) < _NAME_CACHE_MAX:
        _NAME_CACHE[text] = result
    return result


def find_names(text: str) -> list[str]:
    return [name for _, _, name in name_spans(text)]


# Structured payloads label their own fields. A value under `first_name` is a
# name; a value under `testName` is not. Text detection cannot tell them apart:
# on a real clinical API it produced 887 false names and found 1 of 41 real
# identifiers. Keys win when the schema speaks.
NAME_KEYS = re.compile(
    r"^(patient|pt|subject)[_ ]?(full|first|last|middle)?[_ ]?name$"
    r"|^(first|last|middle|full|sur)[_ ]?name$"
    r"|^(name|patient|subject)$", re.I)
RECORD_KEYS = re.compile(
    r"^(mrn|uhid|patient[_ ]?id|subject[_ ]?id|subjectid|suid"
    r"|accession[_ ]?(number|id)?|sample[_ ]?id|specimen[_ ]?id)$", re.I)

# Inside a name object or list, these hold the actual string. FHIR uses `text`,
# `family` and `given`; most APIs use `full`, `display` or `value`.
NAME_PARTS = ("text", "full", "display", "value", "formatted", "family", "given")


def _collect_names(value: object, out: list[str]) -> None:
    """Pull the human-readable strings out of a name field, however nested."""
    if isinstance(value, str):
        if value.strip():
            out.append(value.strip())
    elif isinstance(value, list):
        for item in value:
            _collect_names(item, out)
    elif isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in NAME_PARTS:
                _collect_names(item, out)


def _key_identifiers(payload: object) -> tuple[list[str], list[str]]:
    """Names and record numbers found by the key they sit under."""
    names: list[str] = []
    records: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if NAME_KEYS.match(key) and not isinstance(value, (int, float)):
                    _collect_names(value, names)
                elif isinstance(value, str) and value.strip() and RECORD_KEYS.match(key):
                    records.append(value.strip())
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    return names, records


# Label -> identifier class, for records that were read as fields.
RECORD_LABELS = {
    "name": "names", "provider": "names", "employer": "names",
    "mrn": "mrn", "member": "mrn", "accession": "mrn", "license": "mrn",
    "vehicle": "mrn", "device": "mrn",
    "ssn": "ssn", "dob": "dates", "phone": "phone", "email": "email",
    "address": "geo", "city": "geo", "zip": "geo", "url": "url",
}
# Most sensitive first, so the masked value shown is the worst one.
RECORD_PRIORITY = ("ssn", "mrn", "member", "accession", "license", "name",
                   "provider", "employer", "dob", "phone", "email",
                   "address", "city", "zip", "url")


def _variants(label: str, value: str) -> set[str]:
    """Every form of a name a finding could legitimately be stored as."""
    out = {value}
    if label in ("name", "provider", "employer"):
        if "^" in value:
            parts = [p for p in value.split("^") if p]
            if len(parts) >= 2:
                last, first = parts[0], parts[1]
                for combo in (f"{first} {last}", f"{last} {first}",
                              f"{last}, {first}"):
                    out.add(combo)
                    out.add(combo.title())
        if value.count(",") == 1:
            last, first = [p.strip() for p in value.split(",")]
            if last and first:
                out.add(f"{first} {last}")
        out.add(value.title())
        out.add(value.lower())
    return {v.strip() for v in out if v.strip()}


def identifiers_from_record(text: str) -> dict:
    """Read a labelled record: name=..., mrn=..., dob=..."""
    found: dict[str, list[str]] = {}
    for line in text.splitlines():
        label, _, raw = line.partition("=")
        label = label.strip().lower()
        raw = raw.strip()
        if not raw or label not in RECORD_LABELS:
            continue
        found.setdefault(label, []).extend(_variants(label, raw))

    keys: list[str] = []
    values: list[str] = []
    for label in RECORD_PRIORITY:
        for value in found.get(label, []):
            pool = RECORD_LABELS[label]
            if pool not in keys:
                keys.append(pool)
            values.append(value)

    primary = ""
    for label in RECORD_PRIORITY:
        candidates = found.get(label)
        if candidates:
            primary = candidates[0]
            break

    return {
        "keys": keys,
        "primary": primary,
        "values": values,
        "always": any(label in found for label in ("ssn", "mrn", "member", "accession")),
        "strong": any(label in found for label in ("ssn", "mrn", "member",
                                                   "accession", "name", "provider")),
        "identity": bool(keys),
        "labelled": True,
        "names": [_clean_name(v) for v in _raw_values(text, "name")],
        "ids": [v for label in ("ssn", "mrn", "member", "accession")
                for v in _raw_values(text, label)],
    }


def _raw_values(text: str, label: str) -> list[str]:
    """The values of one field exactly as written, without the name variants."""
    out = []
    for line in text.splitlines():
        key, _, raw = line.partition("=")
        if key.strip().lower() == label and raw.strip():
            out.append(raw.strip())
    return out


def identifiers(text: str, allow_names: bool = True) -> dict:
    # Minified code is adversarial for name detection: identifiers are mangled
    # to one or two letters and UI strings are dense. On the first real target
    # this produced six findings, every one of them nonsense ("New", "Test",
    # "rn(n"). Names are skipped in that case; record numbers and SSNs are not.
    key_names: list[str] = []
    key_records: list[str] = []
    payload: object | None = None
    if text.lstrip().startswith(("{", "[")):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None
    if payload is not None:
        key_names, key_records = _key_identifiers(payload)

    # A source map is code embedded inside JSON. Its identifiers live in an
    # opaque string, not under a key, so the text detector still applies.
    embedded_code = isinstance(payload, dict) and any(
        key in payload for key in ("sourcesContent", "mappings"))

    # Parsed JSON is structured data, and there the text detector is actively
    # harmful: on a real clinical API it emitted 887 false names and found 1 of
    # 41 real identifiers. Keys only, except where the payload is really code.
    if payload is not None and not embedded_code:
        # Values pulled from a name-like key still have to look like names. The
        # stop list applied only to the text detector, so a JSON field called
        # "name" holding "Radiology, MD" was reported as a person.
        names = [name for name in key_names
                 if not any(token.strip(".,'-").lower() in NAME_STOP
                            for token in name.split())]
    else:
        names = find_names(text) if allow_names else []
    mrns = [m.group(0) for m in MRN.finditer(text)]
    for record in key_records:
        if record not in mrns:
            mrns.append(record)
    # A token with the shape this site's labelled ids have is one of them, even
    # where nobody labelled it.
    for shape in _SHAPES:
        for match in shape.finditer(text):
            if match.group(0) not in mrns:
                mrns.append(match.group(0))

    # A bare 6-8 digit run beside a named person is a record number. Without a
    # name in the same record it could be a date, a code or a measurement, and
    # guessing there costs more precision than the recall is worth.
    if names and not mrns:
        for match in BARE_ID.finditer(text):
            mrns.append(match.group(0))
    # A number beside its own label is a record number even without a name.
    for value in _labelled_ids(text):
        if value not in mrns:
            mrns.append(value)

    ssns = [m.group(0) for m in SSN.finditer(text) if ssn_valid(m.group(0))]
    plans = [m.group(0) for m in MBI.finditer(text) if mbi_valid(m.group(0))
             and MBI_LABEL.search(text[max(0, m.start() - 30):m.start()])]
    dobs = [m.group(0) for m in DOB.finditer(text)]
    seen_dates = set(dobs)
    for pattern in (DATE_US, DATE_MONTH, DATE_COMPACT, DATETIME):
        for match in pattern.finditer(text):
            value = match.group(0)
            if value not in seen_dates:
                seen_dates.add(value)
                dobs.append(value)
    phones = [m.group(0) for m in PHONE.finditer(text)]
    emails = [m.group(0) for m in EMAIL.finditer(text)
              if not m.group(0).lower().endswith((".example", ".test", "example.com", "example.org"))]
    ips = [m.group(0) for m in IPV4.finditer(text)
           if not m.group(0).startswith(PRIVATE_IP)]
    zips = [m.group(1) for m in ZIP_CODE.finditer(text)]

    keys: list[str] = []
    if names:
        keys.append("names")
    if mrns:
        keys.append("mrn")
    if ssns:
        keys.append("ssn")
    if plans:
        keys.append("plan_id")
    if dobs:
        keys.append("dates")
    if phones:
        keys.append("phone")
    if emails:
        keys.append("email")
    if ips:
        keys.append("ip")
    if zips:
        keys.append("geo")

    primary = ""
    for pool in (ssns, mrns, plans, names, dobs, phones, emails, zips, ips):
        if pool:
            primary = pool[0]
            break

    return {
        "keys": keys,
        "primary": primary,
        # Every identifier found in the record, so a downstream check can ask
        # "was this value seen here?" without the finding storing any of them.
        "values": [v for pool in (ssns, mrns, plans, names, dobs, phones, emails, zips, ips)
                   for v in pool] + extended_identifiers(text),
        "always": bool(ssns or mrns or plans),
        "strong": bool(names or mrns or ssns or plans),
        "identity": bool(names or mrns or ssns or plans or dobs or phones or zips),
        # For entity resolution only; detect() tokenises them and drops the text.
        "names": names,
        "ids": ssns + mrns,
    }


JWT = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")
PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")
SQL_DDL = re.compile(r"^\s*(?:CREATE|ALTER|DROP|GRANT|REVOKE|SET|USE|BEGIN|COMMIT|LOCK|UNLOCK)\b", re.I)


STREET = re.compile(
    r"\b\d{1,5}\s+(?:[A-Z][a-zA-Z0-9.'-]*\s+){1,4}"
    r"(?:St|Street|Rd|Road|Ave|Avenue|Blvd|Boulevard|Ln|Lane|Dr|Drive|Ct|Court|Way|"
    r"Hwy|Highway|Pkwy|Parkway|Tpke|Turnpike|Ter|Terrace|Pl|Place)\.?", re.I)
FACILITY = re.compile(
    r"\b(?:[A-Z][a-zA-Z'.-]+\s+){1,4}"
    r"(?:Center|Centre|Institute|Hospital|Clinic|Practice|University|Health|"
    r"Medical|Laboratory|Diagnostics|Foundation|Corporation|Association)\b")
PROVIDER = re.compile(
    r"\b(?:Dr\.?\s+)?([A-Z][a-z]+(?:\s+[A-Z]\.)?\s+[A-Z][a-z]+),?\s*"
    r"(?:MD|M\.D\.|DO|D\.O\.|NP|RN|PhD|DDS|PA-C)\b")
# A plan or member id mixes letters and digits. A ten-digit NPI does not, so the
# letter requirement keeps the biggest trap class out.
PLAN = re.compile(
    r"\b(?=[A-Z0-9]{9,15}\b)(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{9,15}\b")
TS14 = re.compile(r"\b(?:19|20)\d{12}\b")
D_MON = re.compile(
    r"\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+"
    r"(?:19|20)\d{2}\b", re.I)
AGE_OVER = re.compile(
    r"\b(?:9\d|1\d\d)\s*[- ]?(?:year|yr)s?[- ]?old\b"
    r"|\bin (?:her|his|their) (?:9\d|1\d\d)s\b"
    r"|\b(?:age|aged)\s+(?:9\d|1\d\d)\b", re.I)
# Five digits is a ZIP; not when it is part of a LOINC code ("12345-6").
ZIP5 = re.compile(r"(?<![\d-])\d{5}(?![\d.-])")


# "DULUTH, MN 55803" and "Bangor, ME": the city is the word before the state.
CITY = re.compile(r"\b([A-Z][a-zA-Z'.-]{2,})\s*,\s*[A-Z]{2}\b")
# A record number after its own label, whatever width it is.
LABELLED_ID = re.compile(
    r"\b(?:mrn|m\.r\.n\.?|record\s*(?:no|number|#)|patient\s*id|acct|account|"
    r"member\s*id|accession)\s*[:#]?\s*([A-Z0-9][A-Z0-9-]{3,})\b", re.I)


def _labelled_ids(text: str) -> list[str]:
    """Ids that follow their own label, and actually contain digits."""
    return [m.group(1) for m in LABELLED_ID.finditer(text)
            if sum(ch.isdigit() for ch in m.group(1)) >= 3]


def extended_identifiers(text: str) -> list[str]:
    """Identifiers this tool does not decide a finding on, but must record.

    A finding already points at a record. Every identifier in that record
    belongs to the same exposure, and a reviewer asking "was this value here?"
    deserves an answer. These never create a finding on their own.
    """
    extra: list[str] = []
    for pattern in (STREET, FACILITY, TS14, D_MON, ZIP5):
        extra.extend(m.group(0).strip() for m in pattern.finditer(text))
    for match in PROVIDER.finditer(text):
        extra.append(match.group(1).strip())
    for match in PLAN.finditer(text):
        extra.append(match.group(0))
    for match in CITY.finditer(text):
        extra.append(match.group(1))
    extra.extend(_labelled_ids(text))
    for match in AGE_OVER.finditer(text):
        extra.append(match.group(0).strip())
    return extra


def decode_jwt(text: str) -> str | None:
    """A JWT carries its claims in the middle segment, in plain base64."""
    stripped = text.strip()
    if not JWT.match(stripped):
        return None
    payload = stripped.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload).decode("utf-8")
    except Exception:  # noqa: BLE001
        return None
    return decoded if decoded.strip() else None


def decode_blob(text: str) -> str | None:
    """Decode a base64 blob, including a blob that was encoded twice.

    Encoding a payload twice defeats a single decode, and costs an attacker one
    more line of code.
    """
    stripped = text.strip()
    decoded: str | None = None
    for _ in range(3):
        if not B64.match(stripped):
            break
        try:
            raw = base64.b64decode(stripped + "=" * (-len(stripped) % 4))
            candidate = raw.decode("utf-8")
        except Exception:  # noqa: BLE001
            break
        if not candidate.isprintable():
            break
        decoded = candidate
        stripped = candidate.strip()
        if not B64.match(stripped):
            break
    return decoded


LINK_KEYS = ("patient_id", "patientId", "subject_id", "subjectId", "person_id")


def units_for(carrier: str, path: str, text: str, derivation: str) -> list[tuple[int, str]]:
    """Split a span into records, returning (offset within the span, text).

    An offset of -1 means "work it out later". That happens for JSON, where the
    serialised object does not appear verbatim in the source.
    """
    # Rendered page text has one line per block element: each line is a record,
    # or a contact paragraph would link to a clinical paragraph further down.
    if derivation in ("pdf_text", "rendered_text"):
        units: list[tuple[int, str]] = []
        offset = 0
        for line in text.splitlines(keepends=True):
            body = line.rstrip("\r\n")
            if body.strip():
                lead = len(body) - len(body.lstrip())
                units.append((offset + lead, body.strip()))
            offset += len(line)
        return units
    if path.endswith(".sql"):
        # One INSERT is one record. Treating the whole dump as a single record
        # hides how many people are in it.
        sql_units: list[tuple[int, str]] = []
        offset = 0
        for line in text.splitlines(keepends=True):
            body = line.rstrip("\r\n")
            # A schema statement describes columns, not people: "name TEXT" is a
            # column definition, and reading it as a person was a false alarm.
            if body.strip() and not body.lstrip().startswith("--") and not SQL_DDL.match(body):
                sql_units.append((offset, body))
            offset += len(line)
        return sql_units or [(0, text)]
    if '"resourceType"' in text:
        # A Patient and a Condition in the same bundle are separate resources
        # joined only by a reference. Nothing in either one identifies a person
        # next to a diagnosis; the link does. Resolving that link is the whole
        # point of FHIR-aware scanning, and a text scanner cannot do it.
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None
        # Only a bundle whose entries actually carry resources is FHIR-shaped.
        # A "Bundle" whose entries are loose fields is just JSON, and treating
        # it as FHIR produced empty records and lost the leak.
        is_bundle = (
            isinstance(payload, dict)
            and payload.get("resourceType") == "Bundle"
            and any(isinstance(entry.get("resource"), dict)
                    for entry in (payload.get("entry") or [])
                    if isinstance(entry, dict))
        )
        if is_bundle:
            by_reference: dict[str, dict] = {}
            for entry in payload.get("entry") or []:
                resource = entry.get("resource") or {}
                if entry.get("fullUrl"):
                    by_reference[entry["fullUrl"]] = resource
                if resource.get("resourceType") == "Patient" and resource.get("id"):
                    by_reference[resource["id"]] = resource

            units: list[tuple[int, str]] = []
            for entry in payload.get("entry") or []:
                resource = entry.get("resource") or {}
                if resource.get("resourceType") == "Patient":
                    continue
                reference = (resource.get("subject") or {}).get("reference")
                patient = by_reference.get(reference) if reference else None
                if patient is not None:
                    units.append((-1, json.dumps(patient) + " " + json.dumps(resource)))
                else:
                    units.append((-1, json.dumps(resource)))
            if units:
                return units
    if path.endswith(".json") and carrier in {"api_response", "downloadable_file",
                                              "api_docs", "fhir_resource"}:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return [(0, text)]
        collected: list[tuple[int, str]] = []

        # An object that points at another by id ("patient_id": "p1") is joined
        # to it, as a FHIR Condition is joined to its Patient. Only objects that
        # carry identity can be the target; a dangling id joins nothing.
        by_id: dict[str, dict] = {}

        def index(node: object) -> None:
            if isinstance(node, dict):
                if isinstance(node.get("id"), (str, int)) and any(_key_identifiers(node)):
                    by_id.setdefault(str(node["id"]), node)
                for value in node.values():
                    index(value)
            elif isinstance(node, list):
                for item in node:
                    index(item)

        index(payload)

        def walk(node: object) -> None:
            if isinstance(node, dict):
                scalars = [v for v in node.values() if isinstance(v, (str, int, float))]
                # A dict holding only lists or other dicts is a container, not a
                # record. Keeping it would produce one finding spanning the whole
                # file and hide the per-record findings underneath it.
                if scalars:
                    target = next((by_id[str(node[key])] for key in LINK_KEYS
                                   if isinstance(node.get(key), (str, int))
                                   and str(node[key]) in by_id
                                   and by_id[str(node[key])] is not node), None)
                    collected.append((-1, json.dumps(node) if target is None
                                      else json.dumps(target) + " " + json.dumps(node)))
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(payload)
        return collected or [(0, text)]
    return [(0, text)]


def rules_for(carrier: str, tags: list[str]) -> list[str]:
    chosen: list[str] = []
    if carrier in WITHHOLD_CARRIERS or carrier == "url":
        chosen.append("transmission_security")
    if carrier == "log":
        chosen.append("activity_review")
    chosen.append("permitted_disclosure")
    if "sud" in tags and "part2_sud" not in chosen:
        chosen.append("part2_sud")
    if "genetic" in tags and "gina" not in chosen:
        chosen.append("gina")
    if "reproductive" in tags and "reproductive_health" not in chosen:
        chosen.append("reproductive_health")
    return chosen


def _span_text(row: dict, vault: Vault) -> tuple[str, str | None] | None:
    """Return (text to analyse, hash of the encoded token if it was decoded)."""
    payload = vault.get(row["doc"])
    raw = payload[row["offset"]:row["offset"] + row["length"]]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # A long base64-looking string is worth decoding whatever carrier it sits
    # in: an attribute, a comment and a script tag are all the same hiding place.
    # A JWT is base64 with dots, so the plain base64 check never fires on it.
    claims = decode_jwt(text)
    if claims is not None:
        return claims, digest(text)
    decoded = decode_blob(text)
    if decoded is not None:
        return decoded, digest(text)
    if row["carrier"] in ("url", "page_link", "third_party") or PERCENT.search(text):
        # "Jane%20Doe" is a name, in a URL or a log; in a query string, so is
        # "John+Gonzales": form encoding writes a space as "+".
        decode = urllib.parse.unquote_plus if "=" in text else urllib.parse.unquote
        return decode(text), digest(text)
    return text, None


MEASURED_AUDIENCE = {"public": "public", "authenticated": "authenticated",
                     "authenticated_other": "authenticated"}
# Order matters only for which reason is reported; any one clears the record.
CLEARING_ORDER = ("own_record", "consented_testimonial", "provider_staff_page",
                  "public_health_article", "company_contact", "code_reference",
                  "group_statistics")


def _record_id(text: str) -> str | None:
    """The id of a JSON record, if the text is one."""
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
    if isinstance(payload, dict):
        for key in ("id", "patient_id", "patientId"):
            if isinstance(payload.get(key), (str, int)):
                return str(payload[key])
    return None


def _cleared_by(record: Record, always: bool) -> tuple[str, str] | None:
    """The first do-not-flag predicate with evidence for this record.

    An always-flag identifier (SSN, MRN, plan id) is never cleared, except as
    the scanning account's own record: that is the tester's own data.
    """
    for name in CLEARING_ORDER:
        if always and name != "own_record":
            continue
        evidence = PREDICATES[name](record)
        if evidence:
            return name, evidence
    return None


def _learn_shapes(texts) -> list[re.Pattern]:
    """Record-number shapes a site uses, learned from its own labelled ids.

    "MRN AAA123456789" teaches AAA999999999; the same shape without a label
    elsewhere is then a record number too. Two distinct labelled values are
    needed so a one-off code is not generalised, and the shape must be long and
    digit-heavy enough that it cannot match ordinary words or years.
    """
    seen: dict[str, set[str]] = {}
    for text in texts:
        for value in _labelled_ids(text):
            shape = "".join("A" if ch.isalpha() else "9" if ch.isdigit() else ch
                            for ch in value)
            seen.setdefault(shape, set()).add(value)
    patterns = []
    for shape in sorted(seen):
        if (len(seen[shape]) >= 2 and len(shape) >= 8
                and any(ch == "A" for ch in shape) and shape.count("9") >= 5):
            body = "".join("[A-Za-z]" if ch == "A" else r"\d" if ch == "9" else re.escape(ch)
                           for ch in shape)
            patterns.append(re.compile(rf"(?<![A-Za-z0-9]){body}(?![A-Za-z0-9])"))
    return patterns


HONORIFICS = {"mr", "mrs", "ms", "miss", "dr", "prof", "sir", "dame"}


def _name_key(name: str) -> str | None:
    """A token for last name plus first initial, so "J. Smith" is "John Smith"."""
    words = re.findall(WORD, name)
    while words and words[0].lower() in HONORIFICS and len(words) > 1:
        words = words[1:]
    if not words:
        return None
    if len(words) == 1:
        return digest("name\0" + words[0].lower())
    first, last = (words[1], words[0]) if "," in name else (words[0], words[-1])
    return digest(f"name\0{last.lower()}\0{first[0].lower()}")


def _resolve_people(findings: list[dict]) -> None:
    """Label findings that refer to the same person, then drop the working keys.

    Union-find over name tokens and record-number/SSN tokens: a record holding
    a name and an MRN ties them together, so the same MRN under another spelling
    of the name is still one person. Only tokens are held, never a name.
    """
    parent: dict[str, str] = {}

    def find(token: str) -> str:
        parent.setdefault(token, token)
        while parent[token] != token:
            parent[token] = parent[parent[token]]
            token = parent[token]
        return token

    for finding in findings:
        tokens = finding["_ids"] + (finding["_names"] if finding["_ids"] else [])
        for token in tokens[1:]:
            parent[find(token)] = find(tokens[0])
    labels: dict[str, str] = {}
    for finding in findings:
        keys = finding.pop("_ids") + finding.pop("_names")
        root = find(keys[0]) if keys else f"alone{len(labels)}"
        finding["person"] = labels.setdefault(root, f"p{len(labels) + 1:03d}")


# Quasi-identifiers (Sweeney 2000: ZIP + birth date + sex single out most people).
# No census table is bundled, so k is not estimated; the three-field rule stands
# in for k < 11.
QUASI_ZIP = re.compile(r"(?i:\bzip(?:[\s_-]*code)?\W{0,4})(\d{5})\b|\b[A-Z]{2}\s+(\d{5})\b")
QUASI_DOB_LABEL = re.compile(r"\b(?:dob|date[\s_-]*of[\s_-]*birth|birth[\s_-]*date|born)\W{0,4}", re.I)
QUASI_SEX = re.compile(r"\b(?:sex|gender)\W{0,4}(?:female|male|woman|man|f|m)\b", re.I)


def _quasi_zip(text: str) -> str | None:
    """The ZIP of a record that has all three quasi-identifiers, else None."""
    zipped = QUASI_ZIP.search(text)
    if not zipped or not QUASI_SEX.search(text):
        return None
    for label in QUASI_DOB_LABEL.finditer(text):
        if any(p.match(text, label.end()) for p in (DOB, DATE_US, DATE_MONTH)):
            return zipped.group(1) or zipped.group(2)
    return None


HEX64 = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")


def _hashed_forms(texts) -> dict[str, tuple[str, str]]:
    """SHA-256 of every email and phone seen, as trackers send them.

    Trackers hash a lowercased, trimmed email or a digits-only phone (with or
    without the country code 1) instead of sending the value. Plain SHA-256 is
    held in memory for this comparison only and is never written anywhere.
    """
    forms: dict[str, tuple[str, str]] = {}

    def add(kind: str, plain: str, normalised: str) -> None:
        forms[hashlib.sha256(normalised.encode("utf-8")).hexdigest()] = (kind, plain)

    for text in texts:
        for match in EMAIL.finditer(text):
            add("email", match.group(0), match.group(0).strip().lower())
        for match in PHONE.finditer(text):
            digits = re.sub(r"\D", "", match.group(0))
            if len(digits) == 11 and digits[0] == "1":
                digits = digits[1:]
            if len(digits) == 10:
                add("phone", match.group(0), digits)
                add("phone", match.group(0), "1" + digits)
    return forms


def detect(index_path: Path, vault_root: Path,
           auth_prefixes: tuple[str, ...] = (),
           context: str = "covered-entity",
           measured: dict[str, str] | None = None,
           own_ids: frozenset[str] = frozenset(),
           cleared: list[dict] | None = None) -> list[dict]:
    """Decide findings.

    context decides the test, not the severity:

      covered-entity  every Safe Harbor identifier of a patient, relative,
                      employer or household member is reportable on its own.
                      Logs, rosters, exports and audit trails count.
                      45 CFR 164.514(b)(2)(i).
      public-web      identity plus a health fact. A page naming a doctor is not
                      an exposure; a page naming a patient and a diagnosis is.

    measured: audience per path from a live capture (public, authenticated,
    authenticated_other, authenticated_self). It overrides auth_prefixes,
    which is only the operator's declaration (spec 2.2: measured, not assumed).
    own_ids: the scanning account's record ids, for a static scan of its data.
    cleared: if given, receives every record a do-not-flag predicate cleared,
    with the evidence for clearing it (policy/negatives.yaml).
    """
    if context not in ("covered-entity", "public-web"):
        raise ValueError(f"unknown context: {context}")
    covered = context == "covered-entity"
    vault = Vault(vault_root)
    global _TOKEN_KEY, _SHAPES
    _TOKEN_KEY = vault.key
    _SHAPES = []
    rows = [json.loads(line) for line in
            Path(index_path).read_text(encoding="utf-8").splitlines() if line]

    # First pass: cache each span's text.
    texts: dict[str, str] = {}
    encoded_hash: dict[str, str | None] = {}
    for row in rows:
        got = _span_text(row, vault)
        if got is None:
            continue
        text, encoded = got
        texts[row["obs_id"]] = text
        encoded_hash[row["obs_id"]] = encoded
    _SHAPES = _learn_shapes(texts.values())

    # Is a file clinical at all? A name in the metadata of a lab report belongs
    # to that report, though the metadata itself says nothing about health.
    # Asked only for files with such a record: running the clinical model over
    # every row of every file just in case was most of detection's time.
    health_by_path: dict[str, bool] = {}

    def clinical(path: str) -> bool:
        if path not in health_by_path:
            health_by_path[path] = any(health(texts[r["obs_id"]])[0] for r in rows
                                       if r["path"] == path and r["obs_id"] in texts
                                       and r["carrier"] != "file_metadata")
        return health_by_path[path]

    # Every identifier present anywhere in a document belongs to that document's
    # exposure. A finding pointing at one paragraph still exposes the phone
    # number in the next one, and a reviewer asking "was this value here?"
    # deserves an answer.
    file_values: dict[str, set[str]] = {}
    pages: dict[str, str] = {}
    raw_seen: set[str] = set()
    for path in {row["path"] for row in rows}:
        joined = "\n".join(texts[row["obs_id"]] for row in rows
                           if row["path"] == path and row["obs_id"] in texts)
        found = identifiers(joined)
        file_values[path] = set(found["values"]) | set(extended_identifiers(joined))
        pages[path] = joined

    # The predicates read the page as served: block elements, JSON-LD markup, a
    # footer. Every row collected with no derivation points into the raw file.
    for row in rows:
        if row["derivation"] == "raw" and row["path"] in pages and row["path"] not in raw_seen:
            raw_seen.add(row["path"])
            raw = vault.get(row["doc"])
            if len(raw) < 2_000_000:
                pages[row["path"]] = raw.decode("utf-8", "replace")

    # The scanning account's own record: labelled by the identity oracle, or a
    # record whose id is the account's own. Its values are not findings anywhere.
    own_values: set[str] = set()
    for path, page in pages.items():
        if (measured or {}).get(path) == "authenticated_self" or (
                own_ids and _record_id(page) in own_ids):
            own_values |= file_values[path]

    findings: list[dict] = []
    for row in rows:
        text = texts.get(row["obs_id"])
        if text is None:
            continue

        aud = MEASURED_AUDIENCE.get((measured or {}).get(row["path"], ""),
                                    audience(row["path"], auth_prefixes))
        cursor = 0
        for unit_offset, unit in units_for(row["carrier"], row["path"], text, row["derivation"]):
            # Minified bundles are marked at collection time; name detection on
            # mangled code produces nonsense. Record numbers are still found.
            # Note: a hand-written .js file can legitimately contain a name, and
            # skipping all .js cost two planted leaks in our own fixture, so the
            # rule stays narrow.
            allow_names = not row["extraction"].startswith("minified")
            labelled = row["extraction"] == "labelled_record"
            # Detection reads the record with its disguises undone; the
            # evidence still points at the bytes as stored.
            seen = normalize(unit)
            ids = (identifiers_from_record(seen) if labelled
                   else identifiers(seen, allow_names=allow_names))

            # A long number in a filename is a record number until proven
            # otherwise: "chart_2024_0012345.txt" is a patient identifier that
            # no body scan will ever see. Rated review, not critical, because a
            # number alone cannot be confirmed.
            filename_id = False
            if not ids["identity"] and row["carrier"] == "url":
                guess = re.search(r"\d{6,}", unit)
                if guess:
                    filename_id = True
                    ids = {"keys": ["record_number"], "primary": guess.group(0),
                           "values": [guess.group(0)], "always": True,
                           "strong": True, "identity": True}
            if not ids["identity"]:
                continue
            if suppression_reason(unit):
                continue

            # No name, record number, SSN or plan id, yet ZIP + birth date + sex
            # is enough to single most people out.
            quasi = None if ids["strong"] else _quasi_zip(seen)
            if quasi is not None:
                position = text.find(quasi, cursor)
                if encoded_hash.get(row["obs_id"]) is not None or position < 0:
                    offset, length = row["offset"], row["length"]
                else:
                    cursor = position + len(quasi)
                    offset, length = row["offset"] + position, len(quasi)
                findings.append({
                    "path": row["path"], "carrier": row["carrier"],
                    "obs_id": row["obs_id"], "doc": row["doc"],
                    "offset": offset, "length": length,
                    "context_offset": row["offset"], "context_length": row["length"],
                    "value_hashes": [digest(quasi)],
                    "extraction": "quasi_identifier",
                    "evidence_grade": row["grade"],
                    "identifiers": ["quasi_identifiers"], "sensitive": [],
                    "level": "review", "rules": rules_for(row["carrier"], []),
                    "value_mask": mask(quasi), "value_hash": digest(quasi),
                    "_names": [], "_ids": [],
                })
                continue

            has_health, tags = health(seen)
            context_health = False
            if row["carrier"] == "file_metadata" and not has_health and clinical(row["path"]):
                # The health context comes from the file, not from this field.
                has_health = True
                context_health = True

            take = False
            weak_only = False
            if covered:
                # Covered entity: an identifier of a patient, relative,
                # employer or household member is reportable on its own, whether
                # it is a labelled field, a log line or a roster column.
                if ids["identity"]:
                    take = True
                    weak_only = not has_health and not ids["always"]
            else:
                # Public web: identity plus a health fact, plus the identifiers
                # that are never safe on their own — a record number or a Social
                # Security number identifies a person with no diagnosis needed.
                if ids["always"]:
                    take = True
                elif row["carrier"] in HIGH_CARRIERS and ids["identity"]:
                    take = True
                elif ids["strong"] and has_health:
                    # A phone number on its own is the organisation's, not a
                    # patient's. Identity means a name, a record number or an SSN.
                    take = True
                elif row["carrier"] in WITHHOLD_CARRIERS and ids["strong"] and has_health:
                    take = True
            if not take:
                continue

            names = find_names(unit) if "names" in ids["keys"] else []
            record = Record(text=unit, page=pages.get(row["path"], ""), path=row["path"],
                            names=names, health=has_health,
                            direct_ids=[v for v in ids["values"] if v not in names],
                            own_values=own_values)
            reason = _cleared_by(record, always=ids["always"])
            if reason is not None:
                if cleared is not None:
                    cleared.append({"path": row["path"], "carrier": row["carrier"],
                                    "predicate": reason[0], "evidence": reason[1],
                                    "value_mask": mask(ids["primary"])})
                continue

            # Evidence points at the exact bytes of the value, not at "somewhere
            # in this observation". Identity is carried separately in
            # value_hashes, so a narrow span never costs us a match.
            encoded = encoded_hash.get(row["obs_id"])
            if encoded is not None:
                offset, length = row["offset"], row["length"]
            else:
                position = text.find(ids["primary"], cursor)
                if position < 0:
                    position = 0
                cursor = position + max(1, len(ids["primary"]))
                offset, length = row["offset"] + position, len(ids["primary"])

            hashes = {digest(v) for v in ids["values"]}
            if covered:
                # Covered-entity reports the document, so the document's
                # identifiers go with it. Public-web keeps one finding per
                # record, which is the invariant the world fixture checks.
                hashes.update(digest(v) for v in file_values.get(row["path"], ()))
            if encoded is not None:
                hashes.add(encoded)

            findings.append({
                "path": row["path"],
                "carrier": row["carrier"],
                "obs_id": row["obs_id"],
                "doc": row["doc"],
                "offset": offset,
                "length": length,
                # The record the value sat in. Evidence points at the value;
                # context is what a reviewer (human or model) needs to judge it.
                "context_offset": row["offset"],
                "context_length": row["length"],
                "value_hashes": sorted(hashes),
                "extraction": row["extraction"],
                "evidence_grade": row["grade"],
                "identifiers": ids["keys"],
                "sensitive": tags,
                "level": ("review" if (filename_id or weak_only
                                       or (labelled and not has_health
                                           and not ids["always"]))
                          else decide(row["carrier"], ids, has_health, aud,
                                      context_health)),
                "rules": rules_for(row["carrier"], tags),
                "value_mask": mask(ids["primary"]),
                "value_hash": digest(ids["primary"]),
                # Working keys for entity resolution; removed before returning.
                "_names": [k for k in (_name_key(n) for n in ids.get("names", []))
                           if k],
                "_ids": [digest(v) for v in ids.get("ids", [])],
            })

    # Trackers send the SHA-256 of an email or phone instead of the value.
    outbound = [row for row in rows if row["carrier"] in ("third_party", "url")
                and row["obs_id"] in texts]
    forms = _hashed_forms(texts.values()) if outbound else {}
    for row in outbound:
        for match in HEX64.finditer(texts[row["obs_id"]].lower()):
            if match.group(0) not in forms:
                continue
            kind, plain = forms[match.group(0)]
            findings.append({
                "path": row["path"], "carrier": row["carrier"],
                "obs_id": row["obs_id"], "doc": row["doc"],
                "offset": row["offset"], "length": row["length"],
                "context_offset": row["offset"], "context_length": row["length"],
                "value_hashes": [digest(plain)],
                "extraction": "hashed_identifier",
                "evidence_grade": row["grade"],
                "identifiers": [kind], "sensitive": [], "level": "critical",
                "rules": rules_for(row["carrier"], []),
                "value_mask": mask(plain), "value_hash": digest(plain),
                "_names": [], "_ids": [],
            })

    # Covered-entity: a document holding identifiers is reported even if no
    # single span held both an identity and a diagnosis. Silence is the worst
    # answer when the file plainly names people.
    if covered:
        covered = {finding["path"] for finding in findings}
        for row in rows:
            path = row["path"]
            if path in covered:
                continue
            values = file_values.get(path)
            text = texts.get(row["obs_id"])
            if not values or not text:
                continue
            covered.add(path)
            sample = sorted(values)[0]
            findings.append({
                "path": path,
                "carrier": row["carrier"],
                "obs_id": row["obs_id"],
                "doc": row["doc"],
                "offset": row["offset"],
                "length": row["length"],
                "context_offset": row["offset"],
                "context_length": row["length"],
                "value_hashes": sorted({digest(v) for v in values}),
                "extraction": row["extraction"],
                "evidence_grade": row["grade"],
                "identifiers": ["record"],
                "sensitive": [],
                "level": "review",
                "rules": rules_for(row["carrier"], []),
                "value_mask": mask(sample),
                "value_hash": digest(sample),
                "_names": [], "_ids": [],
            })

    # One finding per file per value. Prefer the more specific carrier label,
    # then the narrower span: the most precise evidence wins.
    best: dict[tuple[str, str], dict] = {}
    for finding in findings:
        slot = (finding["path"], finding["value_hash"])
        current = best.get(slot)
        if current is None:
            best[slot] = finding
            continue
        # Raw bytes beat rendered text: the same value, but an exact pointer.
        if (rank(finding["carrier"]), finding["extraction"] != "rendered_text",
                -finding["length"]) > (rank(current["carrier"]),
                                       current["extraction"] != "rendered_text",
                                       -current["length"]):
            best[slot] = finding

    # Never order by a token: tokens change with each scan's key, and the same
    # scan must number its findings the same way every time.
    ordered = sorted(best.values(),
                     key=lambda f: (f["path"], f["carrier"], f["obs_id"], f["offset"],
                                    f["length"], f["value_mask"]))
    for index, finding in enumerate(ordered, start=1):
        finding["finding_id"] = f"f{index:05d}"
    # Labels follow the final order, so the same scan labels people the same way.
    _resolve_people(ordered)
    return ordered


def summarise(findings: list[dict]) -> dict:
    levels: dict[str, int] = {}
    carriers: dict[str, int] = {}
    for finding in findings:
        levels[finding["level"]] = levels.get(finding["level"], 0) + 1
        carriers[finding["carrier"]] = carriers.get(finding["carrier"], 0) + 1
    return {
        "findings": len(findings),
        "levels": dict(sorted(levels.items())),
        "carriers": dict(sorted(carriers.items())),
    }
