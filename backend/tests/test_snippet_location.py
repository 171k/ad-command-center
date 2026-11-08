"""Finding-to-source accuracy: snippets must slice from the real source with
true line numbers, reject Semgrep's placeholder, and never fabricate line 1."""
from app.analyzer.engine import SEMGREP_PLACEHOLDER, snippet_from_source

SRC = [f"line{n}" for n in range(1, 21)]  # 20 lines: "line1".."line20"


def test_real_line_numbers_and_hit_span():
    snippet, err = snippet_from_source(SRC, 10, 11, context=2)
    assert err is None
    nums = [s["n"] for s in snippet]
    assert nums == [8, 9, 10, 11, 12, 13]           # real source lines, with context
    hits = [s["n"] for s in snippet if s["hit"]]
    assert hits == [10, 11]                          # matched span highlighted
    assert snippet[2]["text"] == "line10"            # correct text at the real line


def test_context_clamped_at_file_edges():
    snippet, err = snippet_from_source(SRC, 1, 1, context=5)
    assert err is None
    assert snippet[0]["n"] == 1                       # never below line 1
    assert all(1 <= s["n"] <= 20 for s in snippet)


def test_out_of_range_is_explicit_error_not_line_1():
    snippet, err = snippet_from_source(SRC, 9999, 9999)
    assert snippet == []
    assert err and "outside the file" in err          # explicit, no fabricated line 1


def test_placeholder_constant_is_the_semgrep_value():
    # Guards the known Semgrep behaviour we reproduced (extra.lines="requires login").
    assert SEMGREP_PLACEHOLDER == "requires login"


def test_empty_source_errors():
    snippet, err = snippet_from_source([], 1, 1)
    assert snippet == [] and err
