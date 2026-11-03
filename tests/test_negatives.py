import importlib

import yaml

from phi_scan import negatives as n
from phi_scan.negatives import Record


def test_every_declared_predicate_is_implemented():
    declared = yaml.safe_load(open("policy/negatives.yaml", encoding="utf-8"))["predicates"]
    for predicate in declared:
        module, name = predicate["implemented_by"].split(":")
        assert callable(getattr(importlib.import_module(module), name)), name


def test_npi_luhn_with_80840_prefix():
    assert n.npi_valid("1234567893") and not n.npi_valid("1234567890")  # re-exported


def test_provider_page_by_path_markup_or_npi():
    assert n.provider_staff_page(Record("Dr. Helena Marsh, oncology", path="site/team.html"))
    assert n.provider_staff_page(Record("Helena Marsh", page='{"@type": "Physician"}'))
    assert n.provider_staff_page(Record("Dr. Helena Marsh NPI 1234567893"))
    assert not n.provider_staff_page(Record("Patient Jo Ray, NPI 1234567893", path="team.html"))


def test_article_byline_is_not_a_patient():
    rec = Record("Written by Rita Clark. An overview of type 2 diabetes.", names=["Rita Clark"],
                 health=True)
    assert n.public_health_article(rec)
    assert not n.public_health_article(Record("Rita Clark was diagnosed with diabetes.",
                                              names=["Rita Clark"], health=True))


def test_group_counts_and_small_cells():
    assert n.group_statistics(Record("We treated 1,214 patients for diabetes."))
    assert not n.group_statistics(Record("We treated 4 patients for a rare disorder."))
    assert n.small_cell(Record("We treated 4 patients for a rare disorder."))


def test_reserved_values():
    assert n.reserved_value("ssn", "000-12-3456") and n.reserved_value("ssn", "666-12-3456")
    assert n.reserved_value("ssn", "123-00-4567") and n.reserved_value("ssn", "123-45-0000")
    assert n.reserved_value("ssn", "987-65-4325")
    assert not n.reserved_value("ssn", "987-65-4335")  # ITIN-shaped: still an identifier
    assert not n.reserved_value("ssn", "821-49-1456")
    assert n.reserved_value("phone", "(617) 555-0123") and not n.reserved_value("phone", "617-555-2031")
    assert n.reserved_value("email", "sample.patient@example.com")
    assert n.reserved_value("ip", "198.51.100.247") and not n.reserved_value("ip", "8.8.8.8")


def test_company_contact_block():
    page = "<p>x</p><footer>Stonebridge Health Partners | Tel 429-555-5446 | info@sb.example</footer>"
    rec = Record("Stonebridge Health Partners | Tel 429-555-5446 | info@sb.example", page=page)
    assert n.company_contact(rec)


def test_code_reference_needs_no_person():
    assert n.code_reference(Record("E11.9 Type 2 diabetes mellitus without complications"))
    assert not n.code_reference(Record("E11.9 for Jo Ray", names=["Jo Ray"]))


def test_own_record_only_when_every_value_is_ours():
    assert n.own_record(Record("x", names=["Rafael Nilsson"], own_values={"Rafael Nilsson", "MRN-1"}))
    assert not n.own_record(Record("x", names=["Ana Ruiz"], own_values={"Rafael Nilsson"}))


def test_consent_marker_must_be_visible_in_the_record():
    assert n.consented_testimonial(Record("Shared with Rosalind's written permission."))
    assert n.consented_testimonial(Record("Names and details changed."))
    assert not n.consented_testimonial(Record("Read Rosalind's inspiring testimonial."))


def test_consent_marker_in_the_same_paragraph_counts():
    page = "<p>Rosalind Achterberg talks about her transplant. <em>Shared with Rosalind's written permission.</em></p><p>Ana Ruiz, diabetes.</p>"
    assert n.consented_testimonial(Record("Rosalind Achterberg talks about her transplant.", page=page))
    assert not n.consented_testimonial(Record("Ana Ruiz, diabetes.", page=page))


def test_a_name_and_a_condition_without_a_byline_is_not_an_article():
    assert not n.public_health_article(Record("Freya Bhatt - HIV-1 positive", names=["Freya Bhatt"], health=True))


def test_consent_in_a_sibling_cell_or_figure_or_field():
    row = "<table><tr><td>Paige Bartlett</td><td>hypothyroidism</td><td>Shared with written permission</td></tr></table>"
    assert n.consented_testimonial(Record("Paige Bartlett", page=row))
    fig = "<figure><figcaption>John Brown, living with GERD</figcaption><small>Published with John's consent</small></figure>"
    assert n.consented_testimonial(Record("John Brown, living with GERD", page=fig))
    assert n.consented_testimonial(Record('{"name": "Hassan Brown", "consent": "written, on file"}'))
    assert n.consented_testimonial(Record("Testimonial (Published with the person's consent): Xavier Scott"))
    assert not n.consented_testimonial(Record('{"name": "Hassan Brown", "consent": false}'))


def test_organisation_markup_address_and_signature():
    assert n.company_contact(Record('{"@type": "Organization", "telephone": "713-555-7047"}'))
    assert n.company_contact(Record("Phone: 993-555-3006", page="<address><strong>Harbor Care</strong><br>Phone: 993-555-3006</address>"))
    assert n.company_contact(Record("Lakeview Medical Group | Main: 938-555-5214 | info@lakeview.example"))
    assert not n.company_contact(Record("Ana Ruiz, 993-555-3006, diabetes", names=["Ana Ruiz"], health=True))


def test_a_caption_note_right_after_the_figure_counts():
    page = "<figure><figcaption>John Brown, living with GERD</figcaption></figure><small>Fictional account</small><p>Ana Ruiz, asthma.</p>"
    assert n.consented_testimonial(Record("John Brown, living with GERD", page=page))
    assert not n.consented_testimonial(Record("Ana Ruiz, asthma.", page=page))
