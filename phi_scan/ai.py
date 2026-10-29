"""The AI layer. Deliberately the least powerful part of the system.

What the model may do:
    read a redacted record, say whether it looks like a patient, write one
    plain-English paragraph, and suggest lowering the severity by one step.

What the model may never do:
    create a finding, delete a finding, raise a severity, invent a rule id, or
    see a real patient value.

Three defences make "never" true rather than promised:

  1. Redaction happens before the request is built. The model is given
     placeholders, not values, so there is nothing to leak and no BAA needed.
  2. The model's output is validated against a schema and then *applied* by
     ordinary code with hard caps. A model that returns "suppress everything"
     changes nothing, because suppression is not one of the operations.
  3. Page text is untrusted. Instruction-shaped sentences are removed before
     the request and recorded as their own finding, so an attempt to talk the
     scanner out of a result is itself a result.

No API key is needed to test any of this. StubProvider is deterministic, which
is what lets the gate run in CI and lets the comparison be honest.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .detect import DOB, EMAIL, IPV4, MRN, PHONE, SSN, name_spans

B64_RUN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

PLACEHOLDERS = (
    (MRN, "[RECORD_NUMBER]"),
    (SSN, "[SSN]"),
    (DOB, "[DATE]"),
    (PHONE, "[PHONE]"),
    (EMAIL, "[EMAIL]"),
    (IPV4, "[IP]"),
    # An encoded payload is patient data wearing a disguise. A model can decode
    # it, so it must never reach one. Remove it whole rather than trying to
    # redact inside it.
    (B64_RUN, "[ENCODED_PAYLOAD]"),
)

# Phrases that only appear in text trying to instruct the scanner.
INJECTION_PATTERNS = (
    r"ignore (?:all )?(?:previous|prior|above) instructions?",
    r"disregard (?:all )?(?:previous|prior|above)",
    r"you are (?:now )?(?:a|an|the) ",
    r"system prompt",
    r"do not (?:flag|report|include)",
    r"this is not (?:phi|protected health information)",
    r"authori[sz]ed to (?:share|disclose|access)",
    r"override (?:the )?(?:rules|policy|filter)",
    r"instructions?\s*:",
    r"new instructions",
)
INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.I)

# A single sentence, used to cut out an instruction without destroying context.
SENTENCE = re.compile(r"[^.!?\n]+[.!?]?", re.S)

REVIEW_SCHEMA = {
    "required": {
        "finding_id": str,
        "assessment": str,
        "confidence": (int, float),
        "level_recommendation": str,
        "explanation": str,
    },
    "assessment_values": {"patient", "staff", "article", "synthetic", "unclear"},
    "level_values": {"keep", "lower"},
}

# A model may lower a level by one step, never below this floor.
LEVEL_ORDER = ("critical", "high", "medium", "review")
LEVEL_FLOOR_DEFAULT = "medium"
LEVEL_FLOOR_ALWAYS = "high"


def sanitize(text: str) -> tuple[str, list[str]]:
    """Remove sentence-level instruction attempts and report what was removed."""
    hits = [m.group(0) for m in INJECTION_RE.finditer(text)]
    if not hits:
        return text, []

    def scrub(sentence: str) -> str:
        if INJECTION_RE.search(sentence):
            return " [UNTRUSTED-INSTRUCTION-REMOVED] "
        return sentence

    return "".join(scrub(m.group(0)) for m in SENTENCE.finditer(text)), hits


def redact(text: str) -> tuple[str, int]:
    """Replace every identifier with a typed placeholder. Returns count replaced."""
    replaced = 0

    # Names go first, by offset, using the same finder the detector uses.
    # A lookahead pattern cannot be used with subn: it matches zero width, so it
    # would insert placeholders without removing anything. That bug let 40 real
    # names reach a request payload, and gate G4b caught it.
    spans = name_spans(text)
    for start, end, _ in sorted(spans, reverse=True):
        text = text[:start] + "[NAME]" + text[end:]
    replaced += len(spans)

    for pattern, placeholder in PLACEHOLDERS:
        text, count = pattern.subn(placeholder, text)
        replaced += count
    return text, replaced


@dataclass
class Request:
    finding_id: str
    carrier: str
    identifiers: list[str]
    evidence_grade: str
    redacted_context: str
    injection_hits: list[str] = field(default_factory=list)

    def payload(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "carrier": self.carrier,
            "identifiers": self.identifiers,
            "evidence_grade": self.evidence_grade,
            "redacted_context": self.redacted_context,
            "injection_hits": list(self.injection_hits),
        }


def build_request(finding: dict, span_text: str, limit: int = 600) -> Request:
    """Turn a finding into something safe to hand to a model."""
    clean, hits = sanitize(span_text)
    redacted, _ = redact(clean)
    redacted = redacted.strip()[:limit]
    return Request(
        finding_id=finding["finding_id"],
        carrier=finding["carrier"],
        identifiers=list(finding["identifiers"]),
        evidence_grade=finding["evidence_grade"],
        redacted_context=redacted,
        injection_hits=hits,
    )


class Provider:
    name = "abstract"

    def review(self, request: Request) -> dict:
        raise NotImplementedError


class StubProvider(Provider):
    """Deterministic stand-in. Same input, same output, no network.

    It is not a language model and does not pretend to be one. It exists so the
    plumbing, the caps and the injection handling can be tested without a key,
    and so the comparison has a floor to beat.
    """

    name = "stub"

    def review(self, request: Request) -> dict:
        context = request.redacted_context.lower()
        if "npi" in context or "dr." in context:
            assessment = "staff"
        elif "placeholder" in context or "sample" in context or "example" in context:
            assessment = "synthetic"
        elif any(word in context for word in
                 ("carcinoma", "hiv", "diabetes", "depress", "variant", "sclerosis", "hepatitis")):
            assessment = "patient"
        else:
            assessment = "unclear"

        explanation = (
            f"This record was found in {request.carrier.replace('_', ' ')}, "
            f"which is {'not visible' if request.carrier in ('hidden_code', 'css_hidden', 'browser_storage') else 'visible'} "
            f"on the page. It pairs something that points to one person with information about their care. "
            f"It is reported as possible PHI exposure and needs compliance review."
        )
        return {
            "finding_id": request.finding_id,
            "assessment": assessment,
            "confidence": 0.5 if assessment == "unclear" else 0.8,
            "level_recommendation": "lower" if assessment in ("staff", "article", "synthetic") else "keep",
            "explanation": explanation,
        }


class HttpProvider(Provider):
    """The real seam. Not wired until an API key and a deployment posture exist."""

    name = "http"

    def __init__(self, endpoint: str, api_key: str, model: str) -> None:
        self.endpoint = endpoint
        self.api_key = api_key
        self.model = model

    def review(self, request: Request) -> dict:  # pragma: no cover - no key yet
        raise NotImplementedError(
            "No provider configured. Supply an endpoint, a key, and a BAA posture first."
        )


def validate(review: dict) -> list[str]:
    problems: list[str] = []
    for key, kind in REVIEW_SCHEMA["required"].items():
        if key not in review:
            problems.append(f"missing {key}")
        elif not isinstance(review[key], kind):
            problems.append(f"{key} has the wrong type")
    if review.get("assessment") not in REVIEW_SCHEMA["assessment_values"]:
        problems.append(f"assessment '{review.get('assessment')}' is not allowed")
    if review.get("level_recommendation") not in REVIEW_SCHEMA["level_values"]:
        problems.append(f"level_recommendation '{review.get('level_recommendation')}' is not allowed")
    return problems


def apply_review(finding: dict, review: dict) -> dict:
    """Attach the review to a finding. The finding always survives.

    There is deliberately no code path here that removes one. The worst a
    compromised model can do is lower a level by one step, and only down to a
    floor.
    """
    out = dict(finding)
    problems = validate(review)
    out["ai"] = {
        "provider": "stub",
        "valid": not problems,
        "problems": problems,
        "assessment": review.get("assessment"),
        "confidence": review.get("confidence"),
        "explanation": review.get("explanation", ""),
        "requested": review.get("level_recommendation"),
        "applied": "keep",
    }
    if problems:
        return out

    if review["level_recommendation"] == "lower":
        floor = LEVEL_FLOOR_ALWAYS if "always" in finding.get("identifiers", []) else LEVEL_FLOOR_DEFAULT
        floor = LEVEL_FLOOR_ALWAYS if any(
            k in finding.get("identifiers", []) for k in ("ssn", "mrn", "plan_id")) else LEVEL_FLOOR_DEFAULT
        current = finding["level"]
        index = LEVEL_ORDER.index(current) if current in LEVEL_ORDER else 0
        candidate = LEVEL_ORDER[min(index + 1, len(LEVEL_ORDER) - 1)]
        if LEVEL_ORDER.index(candidate) > LEVEL_ORDER.index(floor):
            candidate = floor
        if candidate != current:
            out["level"] = candidate
            out["ai"]["applied"] = "lowered"

    return out


def review_all(findings: list[dict], vault, provider: Provider | None = None) -> tuple[list[dict], list[Request]]:
    """Run every finding through the reviewer, returning annotated findings and requests."""
    provider = provider or StubProvider()
    cache: dict[str, bytes] = {}
    annotated: list[dict] = []
    requests: list[Request] = []

    for finding in findings:
        digest = finding["doc"]
        if digest not in cache:
            cache[digest] = vault.get(digest)
        # The model needs the record, not the value. A bare name tells it
        # nothing and cannot be redacted into anything meaningful.
        start = finding.get("context_offset", finding["offset"])
        size = finding.get("context_length", finding["length"])
        raw = cache[digest][start:start + size]
        try:
            text = raw.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            text = ""
        request = build_request(finding, text)
        requests.append(request)
        annotated.append(apply_review(finding, provider.review(request)))

    return annotated, requests
