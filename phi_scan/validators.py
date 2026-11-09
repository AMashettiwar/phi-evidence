"""Validators, not bare patterns (brief section 5).

A pattern says a string has the right shape. A validator says it could be a
real identifier: a check digit, a structural rule, a plausible date. The
difference is precision. "1234567890" has the shape of an NPI and fails its
check digit; a date in 2087 has the shape of a birth date and is not one.
"""

from __future__ import annotations

import re
from datetime import date

MBI = re.compile(r"^[1-9][AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d[AC-HJKMNP-RT-Y]"
                 r"[AC-HJKMNP-RT-Y0-9]\d[AC-HJKMNP-RT-Y]{2}\d{2}$")
ICD10 = re.compile(r"^[A-TV-Z]\d[0-9AB](?:\.[0-9A-TV-Z]{1,4})?$")
LOINC = re.compile(r"^(\d{1,5})-(\d)$")
DEA = re.compile(r"^([ABCDEFGHJKLMPRSTUX])([A-Z9])(\d{7})$")


def luhn_ok(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        number = int(char)
        if index % 2 == 1:
            number *= 2
            number -= 9 if number > 9 else 0
        total += number
    return total % 10 == 0


def ssn_structural(value: str) -> bool:
    """Could the SSA have issued it? Area 000, 666 and 900-999, group 00 and
    serial 0000 are never issued. (Area 9xx is the ITIN space: not an SSN, still
    an identifier, which is the detector's call, not this function's.)"""
    digits = re.sub(r"\D", "", value)
    if len(digits) != 9:
        return False
    area, group, serial = int(digits[:3]), digits[3:5], digits[5:]
    return area not in (0, 666) and area < 900 and group != "00" and serial != "0000"


def npi_valid(npi: str) -> bool:
    """Ten digits whose Luhn check passes with the card-issuer prefix 80840."""
    return len(npi) == 10 and npi.isdigit() and luhn_ok("80840" + npi)


def dea_valid(value: str) -> bool:
    """Registrant letter, name letter, six digits and a check digit:
    (d1 + d3 + d5) + 2 * (d2 + d4 + d6), last digit equals d7."""
    match = DEA.match(value.replace(" ", "").upper())
    if not match:
        return False
    d = [int(c) for c in match.group(3)]
    return (d[0] + d[2] + d[4] + 2 * (d[1] + d[3] + d[5])) % 10 == d[6]


def icd10_syntax(code: str) -> bool:
    return bool(ICD10.match(code.strip().upper()))


def loinc_valid(code: str) -> bool:
    """LOINC's mod-10 check digit is the Luhn digit of the code body."""
    match = LOINC.match(code.strip())
    return bool(match) and luhn_ok(match.group(1) + match.group(2))


def mbi_valid(value: str) -> bool:
    """Medicare Beneficiary Identifier: eleven characters by CMS position rules,
    letters never S, L, O, I, B or Z. Dashes are display-only."""
    return bool(MBI.match(value.replace("-", "").upper()))


def dob_plausible(value: str, today: date | None = None) -> bool:
    """A real date of birth: parses, not in the future, not over 120 years ago."""
    try:
        born = date.fromisoformat(value)
    except ValueError:
        return False
    today = today or date.today()
    return born <= today and today.year - born.year <= 120
