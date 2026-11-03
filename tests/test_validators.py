from datetime import date

from phi_scan import validators as v


def test_ssn_structure():
    assert v.ssn_structural("821-49-1456")
    for bad in ("000-12-3456", "666-12-3456", "912-34-5678", "123-00-4567", "123-45-0000", "12-34"):
        assert not v.ssn_structural(bad), bad


def test_npi_and_luhn():
    assert v.npi_valid("1234567893") and not v.npi_valid("1234567890")
    assert v.luhn_ok("4111111111111111")


def test_dea_check_digit():
    assert v.dea_valid("AB1234563") and not v.dea_valid("AB1234564") and not v.dea_valid("IB1234563")


def test_icd10_and_loinc():
    assert v.icd10_syntax("E11.9") and v.icd10_syntax("C50.911") and v.icd10_syntax("F33.1")
    assert not v.icd10_syntax("U07") and not v.icd10_syntax("11.9")
    assert v.loinc_valid("2345-7") and v.loinc_valid("4548-4") and not v.loinc_valid("2345-8")


def test_mbi():
    assert v.mbi_valid("1EG4-TE5-MK73") and not v.mbi_valid("1EG4-TE5-MK7S")


def test_dob():
    assert v.dob_plausible("1961-04-03", date(2026, 11, 2))
    assert not v.dob_plausible("2087-01-01", date(2026, 11, 2))
    assert not v.dob_plausible("1850-01-01", date(2026, 11, 2))
    assert not v.dob_plausible("1961-02-30", date(2026, 11, 2))
