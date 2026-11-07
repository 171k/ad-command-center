from conftest import PASSWORD


def test_setup_then_login(client):
    assert client.get("/api/auth/status").json()["account_setup"] is False
    assert client.post("/api/auth/setup", json={"password": PASSWORD}).status_code == 200
    # setup is one-time
    assert client.post("/api/auth/setup", json={"password": "another12345"}).status_code == 409
    r = client.post("/api/auth/login", json={"password": PASSWORD})
    assert r.status_code == 200 and r.json()["csrf_token"]


def test_bad_password_rejected(client):
    client.post("/api/auth/setup", json={"password": PASSWORD})
    assert client.post("/api/auth/login", json={"password": "wrong"}).status_code == 401


def test_login_rate_limit(client):
    client.post("/api/auth/setup", json={"password": PASSWORD})
    codes = [client.post("/api/auth/login", json={"password": "x"}).status_code for _ in range(7)]
    assert 429 in codes  # locked out after configured attempts


def test_unauthenticated_endpoints_blocked(client):
    for path in ("/api/findings", "/api/soc/dashboard", "/api/services", "/api/system/stats"):
        assert client.get(path).status_code == 401


def test_csrf_required_for_mutations(auth):
    client, _ = auth
    # no CSRF header -> 403
    assert client.post("/api/findings", json={"title": "x"}).status_code == 403


def test_concurrent_sessions(client):
    client.post("/api/auth/setup", json={"password": PASSWORD})
    # two independent sessions (separate cookie jars)
    from app.main import app
    from fastapi.testclient import TestClient
    c1 = TestClient(app)
    c2 = TestClient(app)
    r1 = c1.post("/api/auth/login", json={"password": PASSWORD, "label": "P1"})
    r2 = c2.post("/api/auth/login", json={"password": PASSWORD, "label": "P2"})
    assert r1.status_code == 200 and r2.status_code == 200
    # both remain valid simultaneously
    assert c1.get("/api/findings").status_code == 200
    assert c2.get("/api/findings").status_code == 200


def test_logout_and_revoke_all(auth):
    client, h = auth
    assert client.get("/api/findings").status_code == 200
    assert client.post("/api/auth/logout", headers=h).status_code == 200
    assert client.get("/api/findings").status_code == 401


def test_password_rotation_revokes_sessions(auth):
    client, h = auth
    r = client.post("/api/auth/password",
                    json={"current_password": PASSWORD, "new_password": "brandnewpass123"}, headers=h)
    assert r.status_code == 200
    # old session invalid after rotation
    assert client.get("/api/findings").status_code == 401
