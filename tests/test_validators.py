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


def test_age_over_89():
    assert v.age_over_89("1932-05-10", date(2026, 11, 2))
    assert not v.age_over_89("1950-05-10", date(2026, 11, 2))


def test_vin_iso3779_check_digit():
    assert v.vin_valid("1M8GDM9AXKP042788")
    assert v.vin_valid("1HGCM82633A004352")
    assert not v.vin_valid("1M8GDM9A0KP042788")  # wrong check digit at index 8
    assert not v.vin_valid("1M8GDM9AXKP04278I")  # forbidden letter I


def test_udi_and_ipv6_and_restricted_zip3():
    assert v.udi_valid("(01)00844588003288(17)251231(21)SN998811")
    assert v.udi_valid("+H123987654321/SN4455")
    assert not v.udi_valid("(01)00844588003289(17)251231")  # bad GTIN-14 Luhn
    assert v.ipv6_public("2607:f8b0:4005:805::200e")
    assert not v.ipv6_public("::1")
    assert not v.ipv6_public("2001:db8::1")  # RFC 3849 doc range
    assert v.restricted_zip3("03601") and v.restricted_zip3("821")
    assert not v.restricted_zip3("94107")
    assert v.estimate_k_anonymity("821", has_exact_dob=False, has_sex=True, has_rare_dx=True) < 11
    assert v.estimate_k_anonymity("941", has_exact_dob=False, has_sex=True, has_rare_dx=False) >= 11
