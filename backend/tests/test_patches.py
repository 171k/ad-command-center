"""Defense patch management: diff engine, server-validated transitions, locking."""
from app import patching

ORIG = "def q(id):\n    return db.execute('SELECT * FROM u WHERE id=' + id)\n"
PATCHED = "def q(id):\n    return db.execute('SELECT * FROM u WHERE id=?', (id,))\n"


# ---- diff engine (pure) ----

def test_unified_diff():
    d = patching.unified_diff(ORIG, PATCHED, "q.py")
    assert "--- a/q.py" in d and "+++ b/q.py" in d
    assert "-    return db.execute('SELECT * FROM u WHERE id=' + id)" in d
    assert "+    return db.execute('SELECT * FROM u WHERE id=?', (id,))" in d


def test_side_by_side_and_stats():
    rows = patching.side_by_side(ORIG, PATCHED)
    assert rows[0]["type"] == "equal"              # def q(id): unchanged
    assert any(r["type"] == "mod" for r in rows)   # the execute line changed
    stats = patching.diff_stats(ORIG, PATCHED)
    assert stats["modified"] == 1


def test_transition_rules():
    assert patching.transition_error("suggested", "reviewed", {}) is None
    assert patching.transition_error("suggested", "applied", {}) is not None  # skipping steps
    assert patching.transition_error("suggested", "verified", {}) is not None


def test_verified_requires_both_validations():
    p = {"security_status": "pass", "functional_status": "pending"}
    assert patching.transition_error("applied", "verified", p) is not None
    p2 = {"security_status": "pass", "functional_status": "pass"}
    assert patching.transition_error("applied", "verified", p2) is None


# ---- endpoints ----

def _create(client, headers, **kw):
    body = {"title": "sqli fix", "cwe": "CWE-89", "filename": "q.py",
            "original_code": ORIG, "patched_code": PATCHED, "finding_id": "py-sql-string-concat"}
    body.update(kw)
    return client.post("/api/patches", json=body, headers=headers)


def test_create_and_get_with_diff(auth):
    client, headers = auth
    pid = _create(client, headers).json()["id"]
    r = client.get(f"/api/patches/{pid}", headers=headers).json()
    assert r["status"] == "suggested"
    assert "--- a/q.py" in r["unified_diff"]
    assert r["diff_stats"]["modified"] == 1
    assert "reviewed" in r["allowed_transitions"]
    assert any(e["kind"] == "status" for e in r["events"])


def test_status_workflow_and_verify_gate(auth):
    client, headers = auth
    pid = _create(client, headers).json()["id"]
    v = lambda: client.get(f"/api/patches/{pid}", headers=headers).json()["version"]  # noqa: E731

    # invalid skip
    bad = client.post(f"/api/patches/{pid}/status", json={"version": v(), "to_status": "applied"}, headers=headers)
    assert bad.status_code == 400

    for step in ("reviewed", "tested", "applied"):
        r = client.post(f"/api/patches/{pid}/status", json={"version": v(), "to_status": step}, headers=headers)
        assert r.status_code == 200, r.text
    assert v() and client.get(f"/api/patches/{pid}", headers=headers).json()["deployment_status"] == "applied"

    # cannot verify without both validations
    nover = client.post(f"/api/patches/{pid}/status", json={"version": v(), "to_status": "verified"}, headers=headers)
    assert nover.status_code == 400

    client.post(f"/api/patches/{pid}/validation", json={"version": v(), "kind": "security", "result": "pass"}, headers=headers)
    client.post(f"/api/patches/{pid}/validation", json={"version": v(), "kind": "functional", "result": "pass"}, headers=headers)
    ok = client.post(f"/api/patches/{pid}/status", json={"version": v(), "to_status": "verified"}, headers=headers)
    assert ok.status_code == 200
    assert ok.json()["deployment_status"] == "verified"


def test_optimistic_lock_conflict(auth):
    client, headers = auth
    pid = _create(client, headers).json()["id"]
    cur = client.get(f"/api/patches/{pid}", headers=headers).json()["version"]
    # first edit succeeds and bumps version
    client.put(f"/api/patches/{pid}", json={"version": cur, "notes": "a"}, headers=headers)
    # second edit with the stale version conflicts
    conflict = client.put(f"/api/patches/{pid}", json={"version": cur, "notes": "b"}, headers=headers)
    assert conflict.status_code == 409


def test_export_and_delete(auth):
    client, headers = auth
    pid = _create(client, headers).json()["id"]
    exp = client.get(f"/api/patches/{pid}/export", headers=headers)
    assert exp.status_code == 200
    assert exp.headers["content-type"].startswith("text/x-diff")
    assert "+++ b/q.py" in exp.text
    assert client.delete(f"/api/patches/{pid}", headers=headers).status_code == 204
    assert client.get(f"/api/patches/{pid}", headers=headers).status_code == 404
