"""Project scan: upload a zip, extract safely (never execute), scan the tree."""
import io
import time
import zipfile


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in files.items():
            z.writestr(name, content)
    return buf.getvalue()


def _wait_done(client, headers, job_id, timeout=30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/api/defense/scan/{job_id}", headers=headers)
        assert r.status_code == 200
        d = r.json()
        if d["status"] in ("done", "error"):
            return d
        time.sleep(0.2)
    raise AssertionError("scan did not finish in time")


# Patterns the built-in analyzer catches, so the test is deterministic with or
# without Semgrep installed.
VULN_PY = (
    "import subprocess\n"
    "def h(req):\n"
    "    q = 'SELECT * FROM u WHERE id=' + req.args.get('id')\n"
    "    cur.execute(q)\n"
    "    subprocess.run('ping ' + req.args.get('host'), shell=True)\n"
)


def test_scan_zip_groups_findings_by_file(auth):
    client, headers = auth
    data = _zip({
        "service/app.py": VULN_PY,
        "service/readme.md": "# not code",
        "node_modules/skip.js": "eval(x)",  # excluded dir, must not appear
    })
    r = client.post(
        "/api/defense/scan",
        files={"file": ("service.zip", data, "application/zip")},
        headers=headers,
    )
    assert r.status_code == 202
    job_id = r.json()["job_id"]

    d = _wait_done(client, headers, job_id)
    assert d["status"] == "done", d.get("error")
    res = d["result"]
    paths = [f["path"] for f in res["files"]]
    assert "service/app.py" in paths
    assert not any("node_modules" in p for p in paths)
    app_entry = next(f for f in res["files"] if f["path"] == "service/app.py")
    assert len(app_entry["findings"]) >= 2
    f = app_entry["findings"][0]
    for key in ("line", "cwe", "exploit_template", "remediation"):
        assert key in f


def test_scan_rejects_non_zip(auth):
    client, headers = auth
    r = client.post(
        "/api/defense/scan",
        files={"file": ("x.txt", b"not a zip", "text/plain")},
        headers=headers,
    )
    assert r.status_code == 415


def test_scan_status_404(auth):
    client, headers = auth
    r = client.get("/api/defense/scan/999999", headers=headers)
    assert r.status_code == 404


def test_scan_delete(auth):
    client, headers = auth
    data = _zip({"service/app.py": VULN_PY})
    r = client.post("/api/defense/scan", files={"file": ("s.zip", data, "application/zip")}, headers=headers)
    job_id = r.json()["job_id"]
    _wait_done(client, headers, job_id)
    d = client.delete(f"/api/defense/scan/{job_id}", headers=headers)
    assert d.status_code == 204
    assert client.get(f"/api/defense/scan/{job_id}", headers=headers).status_code == 404
    assert client.delete("/api/defense/scan/999999", headers=headers).status_code == 404
