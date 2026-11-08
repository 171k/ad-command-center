"""CWE enrichment: the table that gives every finding an exploit, payload and patch."""
from app.analyzer.enrich import cwe_number, enrich_for_cwe


def test_cwe_number_parse():
    assert cwe_number("CWE-89: SQL Injection") == "89"
    assert cwe_number("cwe_78") == "78"
    assert cwe_number("CWE 502") == "502"
    assert cwe_number(None) is None
    assert cwe_number("no cwe here") is None


def test_enrich_known_cwe_has_all_three():
    e = enrich_for_cwe("CWE-89")
    assert e is not None
    assert e["exploit"] and e["payload"] and e["patch"]
    assert "parameter" in e["patch"].lower()


def test_enrich_alias_maps_to_canonical():
    # CWE-77 (command injection, generic) maps to CWE-78 enrichment.
    assert enrich_for_cwe("CWE-77") == enrich_for_cwe("CWE-78")


def test_enrich_unknown_is_none():
    assert enrich_for_cwe("CWE-99999") is None
    assert enrich_for_cwe("") is None
