from phi_scan.detect import name_spans

ENV = "DEMO_PATIENT_NAME=Freya Bhatt\nDEMO_PATIENT_MRN=MRN-881781\n"


def test_env_line_yields_the_name_not_the_next_key():
    # en_core_web_sm 3.7.1 splits "Freya" and "Bhatt" into two one-word PERSON
    # entities, so this must hold on the regex pass alone.
    names = [span[2] for span in name_spans(ENV)]
    assert "Freya Bhatt" in names


def test_code_identifiers_are_never_name_words():
    names = [span[2] for span in name_spans(ENV)]
    assert not any("_" in name for name in names)
