from phi_scan.normalize import normalize


def test_each_disguise_is_undone():
    assert "639-97-2628" in normalize("Reference: 639-97-2​628")
    assert "Eric Williams" in normalize("Eriс Williams")
    assert "873-69-9040" in normalize("&#56;7&#51;-&#54;9-&#57;&#48;&#52;&#48;")
    assert "730-61-8633" in normalize("‮730-61-8633‬")
    assert "217-22-4353" in normalize("Reference: two one seven - two two - four three five three")
    assert "Medical Record #: 8830800" in normalize("Medical Record #: 883O8OO")
    encoded = "eyJuYW1lIjogIktlbm5ldGggUnlhbiIsICJkaWFnbm9zaXMiOiAiaHlwb3RoeXJvaWRpc20ifQ=="
    assert "Kenneth Ryan" in normalize(f'localStorage.setItem("cache", "{encoded}")')


def test_clean_text_and_real_words_are_left_alone():
    clean = "Freya Bhatt was seen on 2025-03-04. Phone (617) 555-2031."
    assert normalize(clean) == clean
    assert normalize("Москва и Петербург") == "Москва и Петербург"
    assert normalize("Hello, I loved it. Total: 1,240 Oranges") == "Hello, I loved it. Total: 1,240 Oranges"
    assert normalize("one of the two best") == "one of the two best"


def test_substitution_inside_dashed_identifiers():
    assert "149-11-4019" in normalize("Reference: l49-ll-4Ol9")
    assert "641-12-2028" in normalize("64l-l2-2O28")
    assert normalize("Ill lol I-O") == "Ill lol I-O"
    assert normalize("Room 1O, floor 2") == "Room 1O, floor 2"


def test_clinical_model_off_uses_the_term_list_only(monkeypatch):
    import phi_scan.clinical as clinical

    monkeypatch.setenv("PHI_SCAN_CLINICAL_MODEL", "off")
    monkeypatch.setattr(clinical, "_MODEL", None)
    sample = "hosted-demo-only: diagnosed with carcinoma"
    try:
        assert clinical.entities(sample) == []
        assert clinical.health(sample)[0]
    finally:
        clinical._CACHE.pop(sample, None)


def test_names_are_not_diseases_and_cells_are_read():
    from phi_scan.clinical import health
    assert health("Please welcome David Graves, our new treasurer.", ["David Graves"]) == (False, [])
    assert health("Ana Ruiz has Graves disease.", ["Ana Ruiz"])[0]
    assert health("Danielle Martinez | chronic obstructive pulmonary disease")[0]
    assert not health("Harbor Health | 12 Main St Apt. 4, Bangor, ME | info@harbor.example")[0]
