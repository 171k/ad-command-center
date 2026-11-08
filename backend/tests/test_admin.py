"""Admin access control: session management, audit log and feature gates are
restricted to the admin account (itik). Everyone can still change their own password."""

PW = "testpassword123"


def _setup_and_login(client, user):
    client.post("/api/auth/setup", json={"password": PW})  # seeds all team users
    r = client.post("/api/auth/login", json={"username": user, "password": PW})
    assert r.status_code == 200, r.text
    return {"X-CSRF-Token": r.json()["csrf_token"]}


def test_status_reports_admin_flag(client):
    _setup_and_login(client, "itik")
    assert client.get("/api/auth/status").json()["is_admin"] is True
    client.cookies.clear()
    _setup_and_login(client, "mejik")
    assert client.get("/api/auth/status").json()["is_admin"] is False


def test_admin_itik_allowed(client):
    h = _setup_and_login(client, "itik")
    assert client.get("/api/system/audit", headers=h).status_code == 200
    assert client.get("/api/system/config", headers=h).status_code == 200
    assert client.get("/api/auth/sessions", headers=h).status_code == 200
    assert client.post("/api/auth/sessions/revoke-all", headers=h).status_code == 200


def test_non_admin_forbidden(client):
    h = _setup_and_login(client, "namia")
    assert client.get("/api/system/audit", headers=h).status_code == 403
    assert client.get("/api/system/config", headers=h).status_code == 403
    assert client.get("/api/auth/sessions", headers=h).status_code == 403
    assert client.post("/api/auth/sessions/revoke-all", headers=h).status_code == 403


def test_non_admin_can_still_change_password(client):
    h = _setup_and_login(client, "gha")
    r = client.post(
        "/api/auth/password",
        json={"current_password": PW, "new_password": "brandnewpass123"},
        headers=h,
    )
    assert r.status_code == 200


def test_non_admin_can_read_shared_dashboard(client):
    """Shared, non-admin endpoints stay open to the team."""
    h = _setup_and_login(client, "mejik")
    assert client.get("/api/system/stats", headers=h).status_code == 200
    assert client.get("/api/system/activity", headers=h).status_code == 200
