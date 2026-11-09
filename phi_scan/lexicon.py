"""Vocabulary the detector needs, kept separate so it can be reviewed and grown.

The list is split into two, and the split matters:

    HEALTH_TERMS     a specific clinical fact: a condition, a drug class, a
                     result. Only these may create a finding.
    HEALTH_CONTEXT   words that merely suggest medicine is nearby: "treatment",
                     "diagnosis", "admitted". Legal judgments, insurance pages
                     and news articles are full of these. They are recorded but
                     they do not make a record clinical on their own.

That split was forced by gate G5: 31 false findings on 127 court judgments, all
of them institutional names sitting next to the word "treatment".

    NAME_STOP        words that look like a person's name but are not
    SUPPRESS         phrases that mark a record as not-a-patient

This is deliberately a list, not a model. It is inspectable, it is testable, and
when it is wrong you can point at the line that is wrong.
"""

from __future__ import annotations

# Specific clinical facts. term -> sensitivity tags.
HEALTH_TERMS: dict[str, list[str]] = {
    # oncology
    "carcinoma": ["oncology"],
    "cancer": ["oncology"],
    "oncolog": ["oncology"],
    "tumor": ["oncology"],
    "tumour": ["oncology"],
    "lymphoma": ["oncology"],
    "leukemia": ["oncology"],
    "melanoma": ["oncology"],
    "metasta": ["oncology"],
    "malignan": ["oncology"],
    "chemotherap": ["oncology"],
    # infectious
    "hiv": ["hiv"],
    "aids": ["hiv"],
    "hepatitis": [],
    "tuberculosis": [],
    "sepsis": [],
    "septic": [],
    # mental health
    "depress": ["mental_health"],
    "anxiety": ["mental_health"],
    "bipolar": ["mental_health"],
    "schizophren": ["mental_health"],
    "psychiatr": ["mental_health"],
    "psychosis": ["mental_health"],
    # substance use
    "opioid": ["sud"],
    "substance use": ["sud"],
    "alcohol use": ["sud"],
    "addiction": ["sud"],
    "overdose": ["sud"],
    # genetic
    "brca": ["genetic", "oncology"],
    "genetic variant": ["genetic"],
    "pathogenic variant": ["genetic"],
    "genomic": ["genetic"],
    "mutation": ["genetic"],
    "karyotype": ["genetic"],
    # reproductive
    "prenatal": ["reproductive"],
    "pregnan": ["reproductive"],
    "gestation": ["reproductive"],
    "obstetric": ["reproductive"],
    "miscarriage": ["reproductive"],
    # general clinical
    "diabetes": [],
    "renal": [],
    "kidney": [],
    "sclerosis": [],
    "asthma": [],
    "hypertension": [],
    "arthritis": [],
    "dementia": [],
    "alzheimer": [],
    "parkinson": [],
    "epilep": [],
    "stroke": [],
    "fracture": [],
    "anaemia": [],
    "anemia": [],
    # results and investigations, not generic care words
    "hba1c": [],
    "egfr": [],
    "viral load": [],
    "biopsy": [],
    "mri": [],
    "ct scan": [],
    "radiograph": [],
    # coded values that appear in URLs and exports
    "c50.911": ["oncology"],
    "e11.9": [],
    "b20": ["hiv"],
    "f33.1": ["mental_health"],
    "f11.20": ["sud"],
    "z15.01": ["genetic"],
    "z34.90": ["reproductive"],
    "n18.4": [],
    "g35": [],
    "b18.2": [],
}

# Medicine-adjacent words that do NOT on their own make a record clinical.
HEALTH_CONTEXT: tuple[str, ...] = (
    "diagnosis", "diagnoses", "treatment", "treated", "medication",
    "prescription", "admitted", "discharge", "lab result", "laboratory report",
    "test result", "patient", "clinical", "hospital", "medical", "surgery",
    "consultation", "referral", "appointment", "icd-10", "dx=",
)

# Words that make a capitalised pair look like a name but are not one.
NAME_STOP: set[str] = {
    # clinical and organisational
    "health", "medical", "medicine", "oncology", "genetics", "genomic",
    "laboratory", "lab", "center", "centre", "hospital", "clinic", "clinics",
    "services", "service", "group", "inc", "llc", "pc", "pllc", "corp",
    "northbridge", "results", "result", "record", "records", "patient",
    "patients", "open", "read", "more", "your", "details", "last", "visit",
    "review", "routine", "please", "sign", "view", "thank", "summary",
    "care", "team", "our", "clinicians", "board", "certified", "index",
    "backup", "downloads", "files", "roster", "report", "export", "table",
    "history", "account", "settings", "preferences", "search", "enter",
    "term", "above", "questions", "contact", "appointments", "general",
    "information", "this", "page", "does", "not", "describe", "any",
    # product and software words: "Augusta Digital Pathology", a real app's
    # title, was read as the person "Augusta Digital". None is a surname.
    "digital", "online", "mobile", "virtual", "portal", "analytics", "telehealth",
    "labs", "data", "web", "app", "viewer", "catalogue", "catalog",
    # page and job headings a hospital site puts in title case: "Registered
    # Nurse", "Clinical Trials", "Symptoms, Causes and Treatment"
    "registered", "nurse", "nurses", "clinical", "trial", "trials", "symptoms",
    "causes", "follow-up", "developers", "careers", "jobs", "events", "news",
    "library", "stories", "hospitals", "doctors", "physicians", "providers",
    "locations", "insurance", "billing", "privacy", "practices", "notice",
    # clinical phrasing that capitalises at sentence or heading start
    "invasive", "stage", "type", "chronic", "major", "relapsing", "multiple",
    "remitting", "antiretroviral", "therapy", "pathogenic", "variant",
    "weeks", "received", "form", "something", "went", "wrong",
    "traceback", "most", "recent", "call", "error", "line",
    # Anatomy, pathology, specimens and workflow states. Added after the first
    # real target: in a pathology LIMS every specimen and every diagnosis is a
    # capitalised term, so "Lung" was read as a person 68 times and "Bladder"
    # 36. Ordinary prose never shows this.
    "lung", "breast", "colon", "rectum", "prostate", "bladder", "kidney",
    "liver", "brain", "skin", "thyroid", "lymph", "node", "nodes", "bone",
    "marrow", "ovary", "uterus", "cervix", "pancreas", "stomach", "esophagus",
    "oesophagus", "larynx", "oral", "cavity", "head", "neck", "tissue",
    "blood", "serum", "plasma", "urine", "stool", "biopsy", "sample",
    "samples", "specimen", "specimens", "block", "slide", "section",
    "aspirate", "swab", "carcinoma", "adenocarcinoma", "sarcoma", "lymphoma",
    "melanoma", "leukemia", "leukaemia", "tumor", "tumour", "metastasis",
    "metastases", "malignant", "benign", "hyperplasia", "dysplasia",
    "neoplasm", "glioma", "blastoma", "squamous", "cell", "cells", "grading",
    "reserved", "collected", "pending", "completed", "verified", "approved",
    "rejected", "cancelled", "canceled", "accession", "batch", "study",
    "normal", "abnormal", "positive", "negative", "unknown", "other", "none",
    "male", "female", "physician", "surgeon", "pathologist", "technician",
    # Document furniture. Every one of these was reported as a person by a real
    # exam: "PDF", "Blvd", ", MD", "Institute".
    "md", "dds", "dmd", "phd", "rn", "cpa", "esq", "np", "pa",
    "blvd", "boulevard", "avenue", "ave", "street", "road", "lane", "drive",
    "suite", "floor", "parkway", "highway", "apt", "unit",
    # Anatomy in procedure names: "Chest X-ray" on a code list was a person.
    "chest", "abdomen", "abdominal", "pelvis", "pelvic", "spine", "spinal", "knee",
    "shoulder", "skull", "thorax", "x-ray", "xray",
    "institute", "institution", "foundation", "corporation",
    "scan", "scanned", "scanner", "imaging", "diagnostics",
    "pdf", "docx", "xlsx", "pptx", "csv", "json", "jsonl", "xml", "png",
    "jpg", "jpeg", "gif", "tiff", "dcm", "hl7", "x12",
    "report", "reports", "page", "pages", "document", "documents",
    "test", "tests", "result", "results", "value", "values", "unit", "units",
    # legal, institutional and governmental, added after gate G5
    "commission", "court", "courts", "rights", "kingdom", "republic",
    "government", "governments", "council", "parliament", "ministry",
    "department", "section", "protocol", "code", "act", "law", "laws",
    "article", "case", "applicant", "applicants", "state", "states",
    "european", "union", "nations", "organization", "organisation",
    "committee", "assembly", "authority", "agency", "office", "bureau",
    "trust", "foundation", "association", "society", "institute",
    "university", "college", "school", "judge", "judges", "president",
    "registrar", "chamber", "grand", "prosecutor", "lawyer", "advocate",
    "convention", "treaty", "statute", "regulation", "directive",
    "paragraph", "annex", "appendix", "fact", "facts", "circumstances",
    "proceedings", "relevant", "domestic", "international", "national",
    "federal", "military", "public", "second", "first", "third", "final",
    "general", "special", "supreme", "district", "regional", "central",
    # legal phrases, general rather than case-specific
    "procedure", "criminal", "civil", "penal", "appeal", "appeals",
    "constitutional", "administrative", "fundamental", "freedoms",
    "security", "communist", "marxist", "leninist", "workers", "peasants",
    "liberation", "assize", "advocate", "solicitor", "barrister", "tribunal",
    # nationality adjectives, a general category
    "turkish", "german", "french", "british", "irish", "italian", "spanish",
    "polish", "russian", "greek", "dutch", "belgian", "swiss", "austrian",
    "swedish", "norwegian", "danish", "finnish", "portuguese", "hungarian",
    "czech", "romanian", "bulgarian", "croatian", "serbian", "slovenian",
    "slovak", "estonian", "latvian", "lithuanian", "ukrainian", "albanian",
    # honorifics, handled separately
    "mr", "mrs", "ms", "miss", "sir", "dame", "prof",
    # function words
    "the", "in", "of", "and", "for", "with", "from", "at", "to", "on",
    "by", "is", "are", "was", "were", "be", "an", "a", "no", "not",
}

# A record matching any of these is not a patient record.
SUPPRESS: list[tuple[str, str]] = [
    ("NPI", "provider identifier on a staff page"),
    ("Your details", "the signed-in account's own record"),
    ("Your last visit", "the signed-in account's own record"),
    ("All clinicians are board certified", "staff page footer"),
]


def health_hits(text: str) -> tuple[bool, list[str]]:
    """Return whether the text states a specific clinical fact, and its tags.

    Generic medicine-adjacent words are deliberately ignored here. They are
    available through context_hits() for explanations, not for decisions.
    """
    lowered = text.lower()
    tags: list[str] = []
    hit = False
    for term, term_tags in HEALTH_TERMS.items():
        if term in lowered:
            hit = True
            for tag in term_tags:
                if tag not in tags:
                    tags.append(tag)
    return hit, sorted(tags)


def context_hits(text: str) -> list[str]:
    lowered = text.lower()
    return [term for term in HEALTH_CONTEXT if term in lowered]


def suppression_reason(text: str) -> str | None:
    for marker, reason in SUPPRESS:
        if marker in text:
            return reason
    return None
