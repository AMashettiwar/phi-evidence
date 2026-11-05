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

from .lexicon import health_hits

# Substances too common to be a health fact on their own.
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
WORDLIKE = re.compile(r"^[A-Za-z][A-Za-z0-9 ,'/()\-.]*$")
REAL_WORD = re.compile(r"[A-Za-z]{3,}")

_MODEL = None
_CACHE: dict[str, list[tuple[str, str]]] = {}
_CACHE_MAX = 50000
MAX_CHARS = 20000


def _model():
    global _MODEL
    if _MODEL is None:
        import spacy  # noqa: PLC0415

        _MODEL = spacy.load(os.environ.get("PHI_SCAN_CLINICAL_MODEL", "en_ner_bc5cdr_md"))
    return _MODEL


def entities(text: str) -> list[tuple[str, str]]:
    """(text, label) for every DISEASE and CHEMICAL mention, cached by text."""
    cached = _CACHE.get(text)
    if cached is not None:
        return cached
    found = [(e.text, e.label_) for e in _model()(american(text[:MAX_CHARS])).ents]
    if len(_CACHE) < _CACHE_MAX:
        _CACHE[text] = found
    return found


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
    # Table cells and pipe-separated fields are read one by one as well: the
    # model found COPD in prose but not in "Danielle Martinez | COPD".
    segments = [text] + [part for part in CELL_SPLIT.split(text) if len(part) > 2] \
        if CELL_SPLIT.search(text) else [text]
    mentions = [name for segment in segments for name, label in entities(segment)
                if WORDLIKE.match(name) and REAL_WORD.search(name)
                and (label == "DISEASE"
                     or (label == "CHEMICAL" and name.lower() not in COMMON_CHEMICALS
                         # "INT" in a SQL schema and "Apt" in an address are not
                         # drugs; no drug name is shorter than four letters.
                         and len(name) >= 4))
                and not any(name.strip() in person for person in names)]
    if mentions or DISORDER.search(text) or PROCEDURE.search(text):
        hit = True
    evidence = " ".join(mentions) + " " + text
    found = set(tags) | {tag for tag, pattern in TAG_PATTERNS.items()
                         if hit and pattern.search(evidence)}
    return hit, sorted(found)
