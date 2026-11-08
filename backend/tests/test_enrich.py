"""CWE enrichment: the table that gives every finding an exploit, payload and patch."""
from app.analyzer.enrich import cwe_fix_url, cwe_name, cwe_number, enrich_for_cwe, find_cves


def test_cwe_name_and_fix_url():
    assert cwe_name("CWE-22: Improper Limitation of a Pathname") == "Path Traversal"
    assert cwe_name("CWE-89") == "SQL Injection"
    assert cwe_name("CWE-999999") is None
    assert cwe_fix_url("CWE-22") == "https://cwe.mitre.org/data/definitions/22.html"
    assert cwe_fix_url("not a cwe") is None


def test_find_cves():
    cves = find_cves("affected by CVE-2021-44228 and cve-2014-0160")
    ids = {c["id"] for c in cves}
    assert "CVE-2021-44228" in ids and "CVE-2014-0160" in ids
    assert all(c["url"].startswith("https://nvd.nist.gov/vuln/detail/") for c in cves)
    assert find_cves("no cves here") == []


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
