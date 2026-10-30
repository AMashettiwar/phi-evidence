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
import json
import re
import urllib.parse
from pathlib import Path

from .lexicon import NAME_STOP, health_hits, suppression_reason
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
_NLP_LOADED = False

# The model dominates the runtime, and the same strings recur constantly across
# a site (navigation, footers, identical rows). A bounded cache is the cheapest
# large win; it changes no result, only how often the model is asked.
_NAME_CACHE: dict[str, list[tuple[int, int, str]]] = {}
_NAME_CACHE_MAX = 20000


def _load_model():
    """Load the NER model once. A missing model is a supported state, not a crash.

    The model name is configurable so that two models can be compared with the
    same code, and so a deployment can pin an exact model.
    """
    global _NLP, _NLP_LOADED
    if _NLP_LOADED:
        return _NLP
    _NLP_LOADED = True
    try:
        import os  # noqa: PLC0415

        import spacy  # noqa: PLC0415

        _NLP = spacy.load(os.environ.get("PHI_SCAN_MODEL", "en_core_web_sm"))
    except Exception:  # noqa: BLE001
        _NLP = None
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
MRN = re.compile(r"(?<![A-Za-z0-9])MRN[-\s]?\d{3}[\s-]?\d{3,}\b", re.I)
SSN = re.compile(r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b")
DOB = re.compile(r"\b(?:19|20)\d{2}-\d{2}-\d{2}\b")
PHONE = re.compile(r"\(\d{3}\)\s*\d{3}-\d{4}\b")
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
IPV4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
# A word: a letter of any script, then letters, digits, apostrophes or hyphens.
# Capitalisation is enforced in code with str.isupper(), not in the regex, so
# that "İbrahim" and "Güzeler" count as capitalised and "turkey" does not.
# An apostrophe is only part of a word when a letter follows it, so a closing
# quote is never absorbed: 'Rahimi' must not become "Rahimi'".
WORD = r"[^\W\d_](?:[\w\-]|'(?=[^\W\d_]))*"
TITLE_WORD = rf"{WORD}\.?"
# A lookahead, so every adjacent pair is considered. A consuming pattern eats
# the second word of a rejected pair: in "for Emeka Delgado", ("for","Emeka")
# fails the stop list and takes "Emeka" with it, so the real name is never seen.
# This cost two planted leaks and a regression at gate G5 before it was spotted.
NAME = re.compile(rf"(?=\b({WORD}){SEP}({WORD})\b)")
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
CARRIER_RANK = {"page_text": 0, "inline_script": 1}
DEFAULT_RANK = 5


def rank(carrier: str) -> int:
    return CARRIER_RANK.get(carrier, DEFAULT_RANK)


def mask(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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
    if nlp is None:
        return persons, blocked

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
        # "HIV POSITIVE" is an acronym pair, not a person.
        if first.isupper() and last.isupper():
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
        names = key_names
    else:
        names = find_names(text) if allow_names else []
    mrns = [m.group(0) for m in MRN.finditer(text)]
    for record in key_records:
        if record not in mrns:
            mrns.append(record)
    ssns = [m.group(0) for m in SSN.finditer(text) if ssn_valid(m.group(0))]
    dobs = [m.group(0) for m in DOB.finditer(text)]
    phones = [m.group(0) for m in PHONE.finditer(text)]
    emails = [m.group(0) for m in EMAIL.finditer(text)
              if not m.group(0).lower().endswith((".example", ".test", "example.com", "example.org"))]
    ips = [m.group(0) for m in IPV4.finditer(text)
           if not m.group(0).startswith(PRIVATE_IP) and not m.group(0).startswith(TEST_IP)]

    keys: list[str] = []
    if names:
        keys.append("names")
    if mrns:
        keys.append("mrn")
    if ssns:
        keys.append("ssn")
    if dobs:
        keys.append("dates")
    if phones:
        keys.append("phone")
    if emails:
        keys.append("email")
    if ips:
        keys.append("ip")

    primary = ""
    for pool in (ssns, mrns, names, dobs, phones, emails, ips):
        if pool:
            primary = pool[0]
            break

    return {
        "keys": keys,
        "primary": primary,
        # Every identifier found in the record, so a downstream check can ask
        # "was this value seen here?" without the finding storing any of them.
        "values": [v for pool in (ssns, mrns, names, dobs, phones, emails, ips) for v in pool],
        "always": bool(ssns or mrns),
        "strong": bool(names or mrns or ssns),
        "identity": bool(names or mrns or ssns or dobs or phones),
    }


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


def units_for(carrier: str, path: str, text: str, derivation: str) -> list[tuple[int, str]]:
    """Split a span into records, returning (offset within the span, text).

    An offset of -1 means "work it out later". That happens for JSON, where the
    serialised object does not appear verbatim in the source.
    """
    if derivation == "pdf_text":
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
            if body.strip() and not body.lstrip().startswith("--"):
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

        def walk(node: object) -> None:
            if isinstance(node, dict):
                scalars = [v for v in node.values() if isinstance(v, (str, int, float))]
                # A dict holding only lists or other dicts is a container, not a
                # record. Keeping it would produce one finding spanning the whole
                # file and hide the per-record findings underneath it.
                if scalars:
                    collected.append((-1, json.dumps(node)))
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
    decoded = decode_blob(text)
    if decoded is not None:
        return decoded, digest(text)
    if row["carrier"] in ("url", "page_link", "third_party"):
        # "Rafael%20Ibarra" is a name. Evidence stays on the whole URL, so the
        # byte range is still exact.
        return urllib.parse.unquote(text), digest(text)
    return text, None


def detect(index_path: Path, vault_root: Path,
           auth_prefixes: tuple[str, ...] = ()) -> list[dict]:
    vault = Vault(vault_root)
    rows = [json.loads(line) for line in
            Path(index_path).read_text(encoding="utf-8").splitlines() if line]

    # First pass: cache each span's text, and note which files are clinical at
    # all. A name sitting in the metadata of a lab report belongs to that
    # report, even though the metadata itself says nothing about health.
    texts: dict[str, str] = {}
    encoded_hash: dict[str, str | None] = {}
    health_by_path: dict[str, bool] = {}
    for row in rows:
        got = _span_text(row, vault)
        if got is None:
            continue
        text, encoded = got
        texts[row["obs_id"]] = text
        encoded_hash[row["obs_id"]] = encoded
        if health_hits(text)[0]:
            health_by_path[row["path"]] = True

    findings: list[dict] = []
    for row in rows:
        text = texts.get(row["obs_id"])
        if text is None:
            continue

        clinical_file = health_by_path.get(row["path"], False)
        aud = audience(row["path"], auth_prefixes)
        cursor = 0
        for unit_offset, unit in units_for(row["carrier"], row["path"], text, row["derivation"]):
            # Minified bundles are marked at collection time; name detection on
            # mangled code produces nonsense. Record numbers are still found.
            # Note: a hand-written .js file can legitimately contain a name, and
            # skipping all .js cost two planted leaks in our own fixture, so the
            # rule stays narrow.
            allow_names = not row["extraction"].startswith("minified")
            ids = identifiers(unit, allow_names=allow_names)
            if not ids["identity"]:
                continue
            if suppression_reason(unit):
                continue

            has_health, tags = health_hits(unit)
            context_health = False
            if row["carrier"] == "file_metadata" and clinical_file and not has_health:
                # The health context comes from the file, not from this field.
                has_health = True
                context_health = True

            take = False
            if ids["always"]:
                take = True
            elif row["carrier"] in HIGH_CARRIERS and ids["identity"]:
                take = True
            elif ids["strong"] and has_health:
                take = True
            elif row["carrier"] in WITHHOLD_CARRIERS and ids["strong"]:
                take = True
            if not take:
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
                "level": decide(row["carrier"], ids, has_health, aud, context_health),
                "rules": rules_for(row["carrier"], tags),
                "value_mask": mask(ids["primary"]),
                "value_hash": digest(ids["primary"]),
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
        if (rank(finding["carrier"]), -finding["length"]) > (
                rank(current["carrier"]), -current["length"]):
            best[slot] = finding

    ordered = sorted(best.values(),
                     key=lambda f: (f["path"], f["carrier"], f["obs_id"], f["value_hash"]))
    for index, finding in enumerate(ordered, start=1):
        finding["finding_id"] = f"f{index:05d}"
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
