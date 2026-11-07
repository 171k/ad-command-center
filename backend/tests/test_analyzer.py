"""Analyzer rule coverage. Each asserts a real match and honest confidence."""
from app.analyzer import engine


def _ids(result):
    return {f["rule_id"] for f in result["findings"]}


def test_sql_injection_python():
    code = 'q = "SELECT * FROM u WHERE id=" + request.args.get("id")\ncur.execute(q)'
    r = engine.analyze(code, "python", use_semgrep=False)
    assert "py-sql-string-concat" in _ids(r)
    # taint source nearby -> strong
    assert any(f["confidence"] == "strong" for f in r["findings"])


def test_command_injection_shell_true():
    code = 'subprocess.run("ping " + request.args.get("h"), shell=True)'
    r = engine.analyze(code, "python", use_semgrep=False)
    assert "py-cmd-shell-true" in _ids(r)


def test_path_traversal_python():
    code = 'open(os.path.join(base, request.args.get("file")))'
    r = engine.analyze(code, "python", use_semgrep=False)
    assert "py-path-join-input" in _ids(r)


def test_ssti_python():
    code = 'render_template_string("Hi " + request.args.get("name"))'
    r = engine.analyze(code, "python", use_semgrep=False)
    assert "py-jinja-render-string" in _ids(r)


def test_xss_js():
    code = 'el.innerHTML = location.search;'
    r = engine.analyze(code, "javascript", use_semgrep=False)
    assert "js-innerhtml" in _ids(r)


def test_ssrf_python():
    code = 'requests.get(request.args.get("url"))'
    r = engine.analyze(code, "python", use_semgrep=False)
    assert "py-requests-input-url" in _ids(r)


def test_deserialization_python():
    code = 'data = pickle.loads(request.data)'
    r = engine.analyze(code, "python", use_semgrep=False)
    assert "py-pickle-loads" in _ids(r)


def test_eval_python():
    code = 'eval(request.args.get("x"))'
    r = engine.analyze(code, "python", use_semgrep=False)
    assert "py-eval-exec" in _ids(r)


def test_c_unsafe_copy():
    code = 'char buf[10];\nstrcpy(buf, argv[1]);'
    r = engine.analyze(code, "c", use_semgrep=False)
    assert "c-unsafe-copy" in _ids(r)


def test_php_sqli():
    code = '<?php $r = mysqli_query($c, "SELECT * FROM u WHERE id=" . $_GET["id"]); ?>'
    r = engine.analyze(code, "php", use_semgrep=False)
    assert "php-sql-concat" in _ids(r)


def test_no_match_is_not_secure_claim():
    code = 'print("hello world")\nx = 1 + 2'
    r = engine.analyze(code, "python", use_semgrep=False)
    assert r["finding_count"] == 0
    assert r["category_counts"]["none"] == 1
    assert "does NOT prove" in r["no_match_notice"]


def test_confidence_lower_without_taint():
    # eval on a constant is still flagged, but without a nearby taint source
    # it should not be auto-elevated to strong.
    code = 'eval("1 + 1")'
    r = engine.analyze(code, "python", use_semgrep=False)
    assert r["finding_count"] == 1
    assert r["findings"][0]["confidence"] in ("potential", "needs_context")


def test_language_detection():
    assert engine.detect_language("<?php echo $_GET['x']; ?>") == "php"
    assert engine.detect_language("def foo():\n  import os") == "python"
