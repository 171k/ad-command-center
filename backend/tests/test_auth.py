from conftest import PASSWORD


def test_setup_then_login(client):
    assert client.get("/api/auth/status").json()["configured"] is False
    assert client.post("/api/auth/setup", json={"password": PASSWORD}).status_code == 200
    # setup is one-time
    assert client.post("/api/auth/setup", json={"password": "another12345"}).status_code == 409
    r = client.post("/api/auth/login", json={"username": "itik", "password": PASSWORD})
    assert r.status_code == 200 and r.json()["username"] == "itik" and r.json()["csrf_token"]
    # every team user can sign in with the seeded password
    for u in ("mejik", "gha", "namia"):
        assert client.post("/api/auth/login", json={"username": u, "password": PASSWORD}).status_code == 200


def test_bad_password_and_unknown_user(client):
    client.post("/api/auth/setup", json={"password": PASSWORD})
    assert client.post("/api/auth/login", json={"username": "itik", "password": "wrong"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "nobody", "password": PASSWORD}).status_code == 401


def test_login_rate_limit(client):
    client.post("/api/auth/setup", json={"password": PASSWORD})
    codes = [client.post("/api/auth/login", json={"username": "itik", "password": "x"}).status_code for _ in range(7)]
    assert 429 in codes


def test_unauthenticated_endpoints_blocked(client):
    for path in ("/api/findings", "/api/soc/dashboard", "/api/services", "/api/system/stats"):
        assert client.get(path).status_code == 401


def test_csrf_required_for_mutations(auth):
    client, _ = auth
    assert client.post("/api/findings", json={"title": "x"}).status_code == 403


def test_two_users_concurrent_sessions(client):
    client.post("/api/auth/setup", json={"password": PASSWORD})
    from app.main import app
    from fastapi.testclient import TestClient
    a, b = TestClient(app), TestClient(app)
    assert a.post("/api/auth/login", json={"username": "itik", "password": PASSWORD}).status_code == 200
    assert b.post("/api/auth/login", json={"username": "mejik", "password": PASSWORD}).status_code == 200
    # both valid simultaneously; each sees their own identity
    assert a.get("/api/auth/status").json()["username"] == "itik"
    assert b.get("/api/auth/status").json()["username"] == "mejik"


def test_logout(auth):
    client, h = auth
    assert client.get("/api/findings").status_code == 200
    assert client.post("/api/auth/logout", headers=h).status_code == 200
    assert client.get("/api/findings").status_code == 401


def test_password_rotation_signs_out_user(auth):
    client, h = auth
    r = client.post("/api/auth/password",
                    json={"current_password": PASSWORD, "new_password": "brandnewpass123"}, headers=h)
    assert r.status_code == 200
    assert client.get("/api/findings").status_code == 401  # old session invalid
    # new password works, old does not
    assert client.post("/api/auth/login", json={"username": "itik", "password": "brandnewpass123"}).status_code == 200
    assert client.post("/api/auth/login", json={"username": "itik", "password": PASSWORD}).status_code == 401


def test_password_change_is_per_user(auth):
    client, h = auth
    # itik rotates; mejik still logs in with the original seeded password
    client.post("/api/auth/password", json={"current_password": PASSWORD, "new_password": "itikonly12345"}, headers=h)
    assert client.post("/api/auth/login", json={"username": "mejik", "password": PASSWORD}).status_code == 200
