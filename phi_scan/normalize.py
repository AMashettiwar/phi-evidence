"""Undo the ways a value is disguised (brief section 7, adversarial gates).

A detector that sees one form of a value misses every other form. The corpus
plants eight disguises; each is undone here, in this order, before identifiers
and health facts are looked for:

  entities         &#56;7&#51;  ->  873
  invisible        zero-width joiners, soft hyphens, RTL/LTR overrides removed
  homoglyphs       Cyrillic "с" inside a Latin word folded to "c" (only in
                   mixed-script words, so real Cyrillic text is left alone)
  spelled out      "two one seven - two two"  ->  "217-22"
  substitution     "883O8OO" -> "8830800" inside digit-heavy tokens
  base64           embedded runs decoded and appended, so the record inside is read

The result is for detection only. Evidence still points at the stored bytes.
"""

from __future__ import annotations

import base64
import binascii
import html
import re

INVISIBLE = re.compile("[­​-‏‪-‮⁠-⁤⁦-⁩﻿]")
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S", "Ү": "Y",
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "τ": "t",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y", "Ζ": "Z",
})
LATIN = re.compile(r"[A-Za-z]")
NON_LATIN = re.compile(r"[Ͱ-ϿЀ-ӿԀ-ԯ]")
WORD = re.compile(r"\w+", re.UNICODE)
NUMBER_WORDS = {"zero": "0", "oh": "0", "one": "1", "two": "2", "three": "3", "four": "4",
                "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9"}
SPELLED = re.compile(
    r"\b(?:(?:zero|oh|one|two|three|four|five|six|seven|eight|nine)"
    r"(?:\s*(?:-|dash|hyphen)\s*|\s+)){2,}(?:zero|oh|one|two|three|four|five|six|seven|eight|nine)\b",
    re.I)
SUBSTITUTED = re.compile(r"(?<![A-Za-z0-9])[0-9OoIl|][0-9OoIl|-]*[0-9OoIl|](?![A-Za-z0-9])")
ID_SHAPE = re.compile(r"\d{3}-?\d{2}-?\d{4}|\d{5,10}")
B64_RUN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}|\beyJ[A-Za-z0-9+/_-]{20,}={0,2}")


def _fold_homoglyphs(text: str) -> str:
    def fold(match: re.Match) -> str:
        word = match.group(0)
        if LATIN.search(word) and NON_LATIN.search(word):
            return word.translate(CONFUSABLES)
        return word
    return WORD.sub(fold, text)


def _spelled(match: re.Match) -> str:
    out = []
    for token in re.findall(r"[A-Za-z]+|-", match.group(0)):
        lowered = token.lower()
        out.append("-" if lowered in ("-", "dash", "hyphen") else NUMBER_WORDS.get(lowered, ""))
    return "".join(out)


def _unsubstitute(match: re.Match) -> str:
    """Fold O->0 and l/I->1 only where the result is shaped like an identifier
    ("l49-ll-4Ol9" -> 149-11-4019), or the token is mostly digits already.
    A token with no digit at all ("Ill", "lol") is never touched."""
    token = match.group(0)
    digits = sum(c.isdigit() for c in token)
    letters = sum(c in "OoIl|" for c in token)
    if not digits or not letters:
        return token
    folded = token.translate(str.maketrans({"O": "0", "o": "0", "I": "1", "l": "1", "|": "1"}))
    if ID_SHAPE.fullmatch(folded) or (digits >= 4 and letters <= 3):
        return folded
    return token


def _decoded_runs(text: str) -> list[str]:
    found = []
    for run in B64_RUN.findall(text):
        padded = run + "=" * (-len(run) % 4)
        try:
            raw = (base64.urlsafe_b64decode(padded)
                   if "-" in run or "_" in run
                   else base64.b64decode(padded, validate=False))
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded and sum(c.isprintable() for c in decoded) / len(decoded) > 0.95:
            found.append(decoded)
    return found


def normalize(text: str) -> str:
    out = html.unescape(text) if "&" in text else text
    out = INVISIBLE.sub("", out)
    out = _fold_homoglyphs(out)
    out = SPELLED.sub(_spelled, out)
    out = SUBSTITUTED.sub(_unsubstitute, out)
    decoded = _decoded_runs(out)
    return out + ("\n" + "\n".join(decoded) if decoded else "")
