"""Defense code-review endpoints: paste analysis, file upload, Semgrep enrichment."""
import shutil

import pytest

VULN = (
    "import subprocess\n"
    "def ping(host):\n"
    "    return subprocess.run('ping -c1 ' + host, shell=True)\n"
    "q = 'SELECT * FROM users WHERE id = ' + request.args.get('id')\n"
    "cur.execute(q)\n"
)


def test_analyze_paste_reports_line_and_patch(auth):
    client, headers = auth
    r = client.post(
        "/api/defense/analyze",
        json={"code": VULN, "language": "python", "use_semgrep": False},
        headers=headers,
    )
    assert r.status_code == 200
    d = r.json()
    assert d["finding_count"] >= 2
    f = d["findings"][0]
    # every finding exposes the four answers the operator asked for
    for key in ("line", "cwe", "why_dangerous", "exploit_template", "remediation"):
        assert key in f
    assert f["line"] >= 1


def test_analyze_file_upload(auth):
    client, headers = auth
    r = client.post(
        "/api/defense/analyze-file?use_semgrep=false",
        files={"file": ("service.py", VULN, "text/x-python")},
        headers=headers,
    )
    assert r.status_code == 200
    d = r.json()
    assert d["filename"] == "service.py"
    assert d["language"] == "python"
    assert d["finding_count"] >= 2


def test_analyze_file_rejects_binary(auth):
    client, headers = auth
    r = client.post(
        "/api/defense/analyze-file",
        files={"file": ("x.bin", b"\x00\x01\x02binary", "application/octet-stream")},
        headers=headers,
    )
    assert r.status_code == 415


def test_analyze_file_rejects_empty(auth):
    client, headers = auth
    r = client.post(
        "/api/defense/analyze-file",
        files={"file": ("empty.py", b"   \n", "text/plain")},
        headers=headers,
    )
    assert r.status_code == 400


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_semgrep_findings_are_enriched(auth):
    """When Semgrep is installed (Linux CI), its findings carry exploit/payload/patch."""
    client, headers = auth
    code = "import os\ndef h(req):\n    os.system('ping ' + req.args.get('x'))\n"
    r = client.post(
        "/api/defense/analyze",
        json={"code": code, "language": "python", "use_semgrep": True},
        headers=headers,
    )
    assert r.status_code == 200
    d = r.json()
    sg = [f for f in d["findings"] if f.get("engine") == "semgrep"]
    assert sg, "expected at least one Semgrep finding for os.system"
    f = sg[0]
    assert f["why_dangerous"]      # possible exploit
    assert f["exploit_template"]   # example payload
    assert f["remediation"]        # how to patch
    assert f["cwe"].startswith("CWE-")
