"""Known-CVE dependency/runtime scanner foundation."""
import json
from pathlib import Path

from app.analyzer import cve


def test_version_range_matching():
    assert cve.version_in_range("4.17.20", "0", "4.17.21") is True
    assert cve.version_in_range("4.17.21", "0", "4.17.21") is False   # fixed is exclusive
    assert cve.version_in_range("1.2.0", "1.0.0", "1.5.0") is True
    assert cve.version_in_range("2.0.0", "1.0.0", "1.5.0") is False
    assert cve.version_in_range("", "0", "9") is False                # unknown version


def test_parse_package_lock_v3_and_v1():
    v3 = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app"}, "node_modules/lodash": {"version": "4.17.20"}}})
    comps = cve.parse_package_lock(v3, "package-lock.json")
    assert {"npm", "lodash", "4.17.20"} <= {comps[0]["ecosystem"], comps[0]["name"], comps[0]["version"]}
    v1 = json.dumps({"dependencies": {"minimist": {"version": "1.2.0"}}})
    comps1 = cve.parse_package_lock(v1, "package-lock.json")
    assert any(c["name"] == "minimist" and c["version"] == "1.2.0" for c in comps1)


def test_parse_requirements_and_dockerfile():
    reqs = cve.parse_requirements("setuptools==65.5.0\n# c\nflask\n", "requirements.txt")
    assert any(c["name"] == "setuptools" and c["version"] == "65.5.0" for c in reqs)
    assert any(c["name"] == "flask" and c["version"] == "" for c in reqs)
    df = cve.parse_dockerfile_runtime("FROM php:8.1-apache\n", "Dockerfile")
    assert df and df[0]["kind"] == "runtime" and df[0]["name"] == "php" and df[0]["version"] == "8.1-apache"


def _adv_dir(tmp_path: Path, advisories: list[dict]) -> Path:
    d = tmp_path / "adv"
    d.mkdir()
    (d / "a.json").write_text(json.dumps(advisories), encoding="utf-8")
    return d


def test_vulnerable_lockfile_flags_cve(tmp_path, monkeypatch):
    adv = [{"id": "CVE-TEST-0001", "ecosystem": "npm", "package": "demo",
            "ranges": [{"introduced": "0", "fixed": "2.0.0"}], "severity": "high",
            "fixed_version": "2.0.0", "summary": "x", "source": "test"}]
    monkeypatch.setenv("ADCC_ADVISORY_DIR", str(_adv_dir(tmp_path, adv)))
    work = tmp_path / "t"; work.mkdir()
    (work / "package-lock.json").write_text(json.dumps(
        {"lockfileVersion": 3, "packages": {"node_modules/demo": {"version": "1.5.0"}}}))
    rep = cve.scan_tree_for_cves(work, ["package-lock.json"])
    hit = [f for f in rep["findings"] if f["cve"] == "CVE-TEST-0001"]
    assert hit and hit[0]["installed_version"] == "1.5.0"
    assert hit[0]["fixed_version"] == "2.0.0"
    assert "strong" in hit[0]["confidence"]


def test_fixed_version_not_flagged(tmp_path, monkeypatch):
    adv = [{"id": "CVE-TEST-0001", "ecosystem": "npm", "package": "demo",
            "ranges": [{"introduced": "0", "fixed": "2.0.0"}], "severity": "high",
            "fixed_version": "2.0.0", "source": "test"}]
    monkeypatch.setenv("ADCC_ADVISORY_DIR", str(_adv_dir(tmp_path, adv)))
    work = tmp_path / "t"; work.mkdir()
    (work / "package-lock.json").write_text(json.dumps(
        {"lockfileVersion": 3, "packages": {"node_modules/demo": {"version": "2.0.0"}}}))
    rep = cve.scan_tree_for_cves(work, ["package-lock.json"])
    assert not [f for f in rep["findings"] if f["cve"] == "CVE-TEST-0001"]


def test_missing_version_is_undetermined(tmp_path, monkeypatch):
    adv = [{"id": "CVE-TEST-0002", "ecosystem": "PyPI", "package": "demo",
            "ranges": [{"introduced": "0", "fixed": "9"}], "severity": "high", "source": "test"}]
    monkeypatch.setenv("ADCC_ADVISORY_DIR", str(_adv_dir(tmp_path, adv)))
    work = tmp_path / "t"; work.mkdir()
    (work / "requirements.txt").write_text("demo\n")   # no pinned version
    rep = cve.scan_tree_for_cves(work, ["requirements.txt"])
    f = [x for x in rep["findings"] if x["cve"] == "CVE-TEST-0002"]
    assert f and f[0]["confidence"] == "undetermined"


def test_runtime_match_notes_backport(tmp_path, monkeypatch):
    adv = [{"id": "CVE-TEST-PHP", "ecosystem": "runtime", "package": "php",
            "ranges": [{"introduced": "0", "fixed": "8.2"}], "severity": "critical",
            "fixed_version": "8.2", "source": "test"}]
    monkeypatch.setenv("ADCC_ADVISORY_DIR", str(_adv_dir(tmp_path, adv)))
    work = tmp_path / "t"; work.mkdir()
    (work / "Dockerfile").write_text("FROM php:8.1-apache\n")
    rep = cve.scan_tree_for_cves(work, ["Dockerfile"])
    f = [x for x in rep["findings"] if x["cve"] == "CVE-TEST-PHP"]
    assert f and "backport" in f[0]["confidence"]


def test_unsupported_ecosystem_and_no_runtime_limitations(tmp_path, monkeypatch):
    monkeypatch.setenv("ADCC_ADVISORY_DIR", str(_adv_dir(tmp_path, [])))
    work = tmp_path / "t"; work.mkdir()
    # A PHP application source file carries no reliable runtime version.
    (work / "index.php").write_text("<?php echo 1;")
    rep = cve.scan_tree_for_cves(work, ["index.php"])
    assert rep["findings"] == []
    assert any("runtime" in L.lower() for L in rep["limitations"])


def test_seed_advisory_matches_known_cve(tmp_path):
    # The vendored seed should flag an old lodash out of the box.
    work = tmp_path / "t"; work.mkdir()
    (work / "package-lock.json").write_text(json.dumps(
        {"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.20"}}}))
    rep = cve.scan_tree_for_cves(work, ["package-lock.json"])
    assert any(f["cve"] == "CVE-2021-23337" for f in rep["findings"])
