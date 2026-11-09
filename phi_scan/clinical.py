"""Does a record state a health fact? (brief section 5: clinical NER)

The first detector decided this from a hand-typed list of terms, which is the
thing the brief rules out: on the 960-item corpus it missed every condition the
list did not happen to contain, from COPD to glaucoma. A biomedical NER model
trained on disease and chemical mentions (scispaCy's en_ner_bc5cdr_md, BC5CDR
corpus) now answers the question, and the list stays as a second opinion for
the terms it was built for.

Sensitivity tags (spec 2.4) are patterns over what was found. Tagging is not
detection: a pattern here can only raise a level, never create a finding.
"""

from __future__ import annotations

import os
import re

from .lexicon import HEALTH_TERMS, health_hits

# Substances too common to be a health fact on their own.
# All-caps drug abbreviations of four letters or more that notes actually use.
DRUG_ABBREVIATIONS = {"HCTZ", "APAP", "NSAID", "NSAIDS", "SSRI", "SSRIS", "SNRI", "SNRIS",
                      "LMWH", "HAART", "DMARD", "DMARDS", "PPIS", "TMP-SMX", "INSULIN"}
COMMON_CHEMICALS = {"water", "oxygen", "salt", "sugar", "coffee", "tea", "caffeine",
                    "glucose", "sodium", "calcium", "iron", "alcohol", "nicotine",
                    "carbon", "nitrogen", "hydrogen", "vitamin", "protein", "fat"}
DISORDER = re.compile(
    r"\b(?:alcohol|opioid|stimulant|cocaine|cannabis|methamphetamine|heroin|nicotine|"
    r"substance|gambling)\s+(?:use disorder|dependence|addiction|abuse|withdrawal)\b", re.I)
TAGS = {
    "oncology": r"cancer|carcinoma|leuk(?:a)?emia|lymphoma|tumou?r|melanoma|sarcoma|myeloma|"
                r"metasta|oncolog|neoplasm|chemotherapy",
    "hiv": r"\bhiv\b|\baids\b|antiretroviral",
    "mental_health": r"depress|anxiety|bipolar|schizo|ptsd|psychos|psychiatr|adhd|"
                     r"anorexia|bulimia|suicid|obsessive|panic disorder|personality disorder",
    "sud": r"use disorder|dependence|addiction|opioid|naltrexone|buprenorphine|methadone|"
           r"withdrawal|detox",
    "reproductive": r"pregnan|infertil|gestation|prenatal|abortion|\bivf\b|contracept|"
                    r"miscarriage|obstetric|fertility",
    "genetic": r"brca|genetic|variant|mutation|f508del|huntington|homozygous|heterozygous|"
               r"carrier status|chromosom",
}
TAG_PATTERNS = {tag: re.compile(pattern, re.I) for tag, pattern in TAGS.items()}
# The model reads code as prose: in a stylesheet it called "@media" a disease and
# "} }" a chemical. A mention must look like words to count.
# A diagnosis field: a structured record's "dx=" line, or a link's query
# parameter ("confirm?patient=Walter+Briggs&dx=C61" in a real-looking sitemap).
LABELLED_DX = re.compile(r"(?:^|[?&;])(?:dx|diagnosis|icd_?10|icd)=\w", re.M | re.I)
# Procedures and tests. The disease/chemical model was trained on neither, so a
# colonoscopy, a mastectomy or IVF was no health fact at all (independent
# probes, tests/probes_prose.py). Medical word formation covers most procedures;
# the rest are a short list of head nouns. Licensed terminologies (SNOMED, CPT)
# would do this better; the public ICD-10-PCS was not downloaded (stated in
# tasks/todo.md).
PROCEDURE = re.compile(
    r"\b[a-z]+(?:ectomy|otomy|ostomy|oscopy|plasty|centesis|pexy|rrhaphy|tripsy|graphy)\b"
    r"|\b(?:knee|hip|joint|valve|heart|kidney|liver|lung|cornea|bone marrow)\s+"
    r"(?:replacement|transplant(?:ation)?)\b"
    r"|\b(?:transplant(?:ation)?|biops(?:y|ies)|dialysis|chemotherapy|radiotherapy|"
    r"catheteri[sz]ation|stent(?:ing)?|angioplasty|ivf|in vitro fertili[sz]ation|"
    r"physiotherapy|physio|mri|ct scan|pet scan|mammogram|transfusion|"
    r"rotator cuff|fracture[sd]?|herniated|ligament tear)\b", re.I)
# British spellings the model does not know: "leukaemia" found nothing.
BRITISH = [(re.compile(p, re.I), r) for p, r in (
    (r"aemia", "emia"), (r"haem", "hem"), (r"oedem", "edem"), (r"oesophag", "esophag"),
    (r"paed", "ped"), (r"tumour", "tumor"), (r"foet", "fet"), (r"diarrhoea", "diarrhea"),
    (r"oestro", "estro"), (r"gynaec", "gynec"), (r"leukaem", "leukem"))]


def american(text: str) -> str:
    for pattern, replacement in BRITISH:
        text = pattern.sub(replacement, text)
    return text
CELL_SPLIT = re.compile(r"\s*[|;\t]\s*")
CODE_IDENTIFIER = re.compile(r"^[A-Z][a-z]+(?:[A-Z][a-z]+)+\b")
WORDLIKE = re.compile(r"^[A-Za-z][A-Za-z0-9 ,'/()\-.]*$")
REAL_WORD = re.compile(r"[A-Za-z]{3,}")

_MODEL = None
_CACHE: dict[str, list[tuple[str, str]]] = {}
_CACHE_MAX = 50000
_OVERFLOW: dict[str, list[tuple[str, str]]] = {}  # one batch's answers once the cache is full
MAX_CHARS = 20000


def _model():
    global _MODEL
    if _MODEL is None:
        import spacy  # noqa: PLC0415

        _MODEL = spacy.load(os.environ.get("PHI_SCAN_CLINICAL_MODEL", "en_ner_bc5cdr_md"))
    return _MODEL


def entities(text: str) -> list[tuple[str, str]]:
    """(text, label) for every DISEASE and CHEMICAL mention, cached by text."""
    return entities_many([text])[0]


def entities_many(texts: list[str]) -> list[list[tuple[str, str]]]:
    """entities() for many texts, the uncached ones read in one batch. The same
    answers as one call each, without the per-call overhead: a FHIR server's
    page split into 30,000 table cells took eight minutes one at a time."""
    missing = list(dict.fromkeys(t for t in texts if t not in _CACHE))
    if missing:
        docs = _model().pipe((american(t[:MAX_CHARS]) for t in missing), batch_size=256)
        for text, doc in zip(missing, docs):
            found = [(e.text, e.label_) for e in doc.ents]
            if len(_CACHE) < _CACHE_MAX:
                _CACHE[text] = found
            else:
                _OVERFLOW[text] = found
    result = [_CACHE.get(t) if t in _CACHE else _OVERFLOW.get(t, []) for t in texts]
    _OVERFLOW.clear()
    return result


def _mentions(text: str, names: list[str] | tuple) -> list[str]:
    """Disease and drug mentions the model finds, as health() counts them."""
    # Table cells and pipe-separated fields are read one by one as well: the
    # model found COPD in prose but not in "Danielle Martinez | COPD". Only
    # within the MAX_CHARS the whole-text pass reads, so a huge page is not
    # split into tens of thousands of cells.
    head = text[:MAX_CHARS]
    segments = [text] + [part for part in CELL_SPLIT.split(head) if len(part) > 2] \
        if CELL_SPLIT.search(head) else [text]
    found = entities_many(segments)
    return [name for labelled in found for name, label in labelled
            if WORDLIKE.match(name) and REAL_WORD.search(name)
            # "MolecularSequence", "AllergyIntolerance": capitalised words run
            # together are a FHIR type or a class name, never clinical prose.
            and not CODE_IDENTIFIER.match(name)
            and (label == "DISEASE"
                 or (label == "CHEMICAL" and name.lower() not in COMMON_CHEMICALS
                     # "INT" in a SQL schema and "Apt" in an address are not
                     # drugs; no drug name is shorter than four letters.
                     and len(name) >= 4
                     # Nor is "HFQL" (a FHIR server's query language): an
                     # all-caps "chemical" is an acronym unless it is a
                     # drug abbreviation clinicians write.
                     and (not name.isupper() or name in DRUG_ABBREVIATIONS)))
            and not any(name.strip() in person for person in names)]


def health_positions(text: str, names: list[str] | tuple = ()) -> list[int]:
    """Where in the text each health fact health() would count sits. One model
    pass (cached), so a long block need not be re-read per name."""
    lowered = text.lower()
    spots = [m.start() for term in HEALTH_TERMS if term in lowered
             for m in re.finditer(re.escape(term), lowered)]
    spots += [m.start() for pattern in (LABELLED_DX, DISORDER, PROCEDURE)
              for m in pattern.finditer(text)]
    spots += [m.start() for mention in set(_mentions(text, names))
              for m in re.finditer(re.escape(mention), text)]
    return spots


def health(text: str, names: list[str] | tuple = ()) -> tuple[bool, list[str]]:
    """Whether the text states a clinical fact, and its sensitivity tags.

    names: people already found in the record. The model reads eponyms into
    names ("David Graves" as Graves' disease, "Duane" as Duane syndrome), so a
    mention that is, or sits inside, a person's name is not a health fact.
    "Graves disease" written out still is."""
    hit, tags = health_hits(text)
    # A structured record's diagnosis field is health content by its label,
    # whether it holds a description or a bare code (structured.py).
    if LABELLED_DX.search(text):
        hit = True
    if not any(c.isalpha() for c in text):
        return hit, tags
    mentions = _mentions(text, names)
    if mentions or DISORDER.search(text) or PROCEDURE.search(text):
        hit = True
    evidence = " ".join(mentions) + " " + text
    found = set(tags) | {tag for tag, pattern in TAG_PATTERNS.items()
                         if hit and pattern.search(evidence)}
    return hit, sorted(found)
