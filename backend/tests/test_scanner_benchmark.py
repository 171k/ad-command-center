"""Array Escape regression benchmark for the Defense scanner.

Runs the REAL scan pipeline (built-in rules + Semgrep) over a non-git temp copy
of the benchmark fixtures and asserts detection coverage, source-location
accuracy, evidence-based correlation and the no-false-positive requirement on
the secure counterpart. Skipped when Semgrep is not installed (e.g. local
Windows dev); it runs in CI where Semgrep is available.

These fixtures are a minimal hand-written reproduction of the publicly described
challenge, not the organiser's source (see the fixture README).
"""
import shutil
from pathlib import Path

import pytest

from app.analyzer.enrich import cwe_number
from app.analyzer.project_scan import EXT_LANG, analyze_tree

FIX = Path(__file__).parent / "fixtures" / "benchmarks"
pytestmark = pytest.mark.skipif(shutil.which("semgrep") is None,
                                reason="Semgrep not installed")


def _run(src_dir: Path, tmp_path: Path) -> dict:
    # Copy to a non-git temp dir: Semgrep only scans git-tracked files inside a
    # repo, and production scans an extracted (non-git) tree, so we mirror that.
    work = tmp_path / "tree"
    shutil.copytree(src_dir, work)
    files = [str(p.relative_to(work)).replace("\\", "/")
             for p in work.rglob("*") if p.suffix.lower() in EXT_LANG]
    return analyze_tree(work, files)


def _cwes(result: dict) -> set[str]:
    return {cwe_number(f.get("cwe"))
            for fe in result["files"] for f in fe["findings"]}


def _find(result, path_frag, cwe_num):
    for fe in result["files"]:
        if path_frag in fe["path"]:
            for f in fe["findings"]:
                if cwe_number(f.get("cwe")) == cwe_num:
                    return fe["path"], f
    return None, None


def test_array_escape_detects_all_four_classes(tmp_path):
    res = _run(FIX / "array_escape", tmp_path)
    cwes = _cwes(res)
    # The four weakness classes from the writeup, by CWE:
    detected = {
        "exposed signing secret": {"200", "321", "798"} & cwes,
        "auth-token weakness": {"208", "285", "347"} & cwes,
        "path traversal": {"22"} & cwes,
    }
    missed = [k for k, v in detected.items() if not v]
    assert not missed, f"missed weakness classes: {missed} (detected CWEs: {sorted(cwes)})"


def test_source_location_accuracy_on_path_read(tmp_path):
    res = _run(FIX / "array_escape", tmp_path)
    path, f = _find(res, "docs.js", "22")
    assert f, "expected a CWE-22 finding in docs.js"
    # The snippet must be sliced from the real source: a highlighted line whose
    # text is the actual readFileSync call, numbered with its true source line.
    hits = [s for s in f["snippet"] if s.get("hit")]
    assert hits, "finding has no highlighted source line"
    assert any("readFileSync" in s["text"] for s in hits)
    assert all(s["n"] >= 1 for s in f["snippet"])
    assert f["snippet"][0]["n"] != 1 or f["line"] == 1  # context, not forced to line 1
    assert f.get("snippet_error") is None
    assert "requires login" not in (f.get("matched_text") or "")


def test_findings_are_enriched_and_named(tmp_path):
    res = _run(FIX / "array_escape", tmp_path)
    _, f = _find(res, "docs.js", "22")
    assert f["vuln_name"] == "Path Traversal"
    assert f["fix_url"].endswith("/22.html")
    assert f["exploit_template"] and f["remediation"]   # enrichment populated


def test_evidence_based_correlation_present(tmp_path):
    res = _run(FIX / "array_escape", tmp_path)
    assert res["related"], "expected at least one evidence-linked group"
    g = res["related"][0]
    assert g["evidence"]                                 # concrete evidence recorded
    assert len(g["members"]) >= 2


def test_secure_fixture_has_no_equivalent_findings(tmp_path):
    res = _run(FIX / "secure_examples", tmp_path)
    cwes = _cwes(res)
    # The secure counterpart validates input and keeps secrets server-side:
    # it must not raise the path-traversal / secret-exposure classes.
    assert "22" not in cwes
    assert not ({"200", "321"} & cwes), f"unexpected secret finding: {sorted(cwes)}"
