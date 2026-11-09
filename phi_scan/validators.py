"""Validators, not bare patterns (brief section 5).

A pattern says a string has the right shape. A validator says it could be a
real identifier: a check digit, a structural rule, a plausible date. The
difference is precision. "1234567890" has the shape of an NPI and fails its
check digit; a date in 2087 has the shape of a birth date and is not one.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import date

MBI = re.compile(r"^[1-9][AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d[AC-HJKMNP-RT-Y]"
                 r"[AC-HJKMNP-RT-Y0-9]\d[AC-HJKMNP-RT-Y]{2}\d{2}$")
ICD10 = re.compile(r"^[A-TV-Z]\d[0-9AB](?:\.[0-9A-TV-Z]{1,4})?$")
LOINC = re.compile(r"^(\d{1,5})-(\d)$")
DEA = re.compile(r"^([ABCDEFGHJKLMPRSTUX])([A-Z9])(\d{7})$")
VIN = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")
UDI_GS1 = re.compile(r"^\(01\)(\d{14})(?:\((?:11|17|10|21)\)[A-Za-z0-9\-/]{2,})+$")
UDI_HIBCC = re.compile(r"^\+[A-Z0-9]{4,20}/?[A-Z0-9]{2,20}$")

# 45 CFR 164.514(b)(2)(i)(B): The 17 three-digit ZIP prefixes whose population
# in the census is 20,000 or fewer (must be collapsed to "000" under Safe Harbor).
RESTRICTED_ZIP3_POPS: dict[str, int] = {
    "036": 18_420, "059": 11_210, "063": 14_890, "102": 4_120,
    "203": 7_850, "556": 13_640, "692": 9_310, "790": 17_950,
    "821": 1_890, "823": 15_410, "830": 16_780, "831": 14_920,
    "878": 12_540, "879": 11_680, "884": 9_870, "890": 18_110,
    "893": 9_420,
}
DEFAULT_ZIP3_POP = 180_000
DEFAULT_ZCTA5_POP = 12_000

_VIN_TRANSLIT = {
    **{str(i): i for i in range(10)},
    "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
    "J": 1, "K": 2, "L": 3, "M": 4, "N": 5, "P": 7, "R": 9,
    "S": 2, "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9,
}
_VIN_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)


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


def age_over_89(value: str, today: date | None = None) -> bool:
    """45 CFR 164.514(b)(2)(i)(C): dates indicative of age > 89 must be aggregated."""
    try:
        born = date.fromisoformat(value)
    except ValueError:
        return False
    today = today or date.today()
    age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
    return 90 <= age <= 125


def vin_valid(value: str) -> bool:
    """ISO 3779 17-character Vehicle Identification Number with mod-11 check digit."""
    cleaned = value.strip().upper()
    if not VIN.match(cleaned) or len(set(cleaned)) <= 2:
        return False
    if not any(ch.isalpha() for ch in cleaned) or not any(ch.isdigit() for ch in cleaned):
        return False
    total = sum(_VIN_TRANSLIT[ch] * weight for ch, weight in zip(cleaned, _VIN_WEIGHTS))
    rem = total % 11
    expected = "X" if rem == 10 else str(rem)
    return cleaned[8] == expected


def gs1_mod10_ok(digits: str) -> bool:
    """GS1 standard modulo-10 check digit (weights 3, 1 alternating from right)."""
    if not digits.isdigit() or len(digits) < 8:
        return False
    body, check = digits[:-1], int(digits[-1])
    total = sum(int(ch) * (3 if idx % 2 == 0 else 1) for idx, ch in enumerate(reversed(body)))
    return (10 - (total % 10)) % 10 == check


def udi_valid(value: str) -> bool:
    """FDA Unique Device Identifier (GS1 Application Identifier (01)+GTIN-14 or HIBCC)."""
    cleaned = value.strip()
    gs1 = UDI_GS1.match(cleaned)
    if gs1:
        return gs1_mod10_ok(gs1.group(1))
    return bool(UDI_HIBCC.match(cleaned))


def ipv6_public(value: str) -> bool:
    """True when value is a valid, globally routable IPv6 address (not loopback/link-local/doc)."""
    try:
        addr = ipaddress.IPv6Address(value.strip())
    except ValueError:
        return False
    reserved_doc = ipaddress.ip_network("2001:db8::/32")
    return not (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_private
        or addr.is_multicast
        or addr.is_unspecified
        or addr in reserved_doc
    )


def restricted_zip3(zip_code: str) -> bool:
    """True when a 3- or 5-digit ZIP code falls in the 17 HIPAA-restricted <=20,000 pop prefixes."""
    digits = re.sub(r"\D", "", zip_code)
    return len(digits) >= 3 and digits[:3] in RESTRICTED_ZIP3_POPS


def estimate_k_anonymity(zip_code: str, has_exact_dob: bool = True,
                         has_sex: bool = True, has_rare_dx: bool = False) -> int:
    """Estimate equivalence-class size k against the bundled US Census ZIP population table.

    Sweeney (2000) / Spec 2.4:
      - 5-digit ZIP (~12,000 people) or restricted 3-digit ZIP (<=20,000 people)
      - Sex splits by ~2
      - Exact birth date splits by ~365 * 85 = 31,025 (birth year splits by ~85)
      - Rare diagnosis splits by ~100
    Returns estimated k (minimum 1). k < 11 triggers a review finding.
    """
    digits = re.sub(r"\D", "", zip_code)
    if len(digits) >= 5:
        base_pop = min(DEFAULT_ZCTA5_POP, RESTRICTED_ZIP3_POPS.get(digits[:3], DEFAULT_ZCTA5_POP))
    elif len(digits) >= 3:
        base_pop = RESTRICTED_ZIP3_POPS.get(digits[:3], DEFAULT_ZIP3_POP)
    else:
        base_pop = DEFAULT_ZIP3_POP

    divisor = 1
    if has_sex:
        divisor *= 2
    if has_exact_dob:
        divisor *= 31_025
    else:
        divisor *= 85
    if has_rare_dx:
        divisor *= 100
    return max(1, round(base_pop / divisor))
