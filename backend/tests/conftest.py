"""Test fixtures. A temp DB is configured via env BEFORE importing the app, so
the whole suite runs against an isolated database that is reset per test."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

_TMP = Path(tempfile.gettempdir()) / "adcc_test"
_TMP.mkdir(exist_ok=True)
os.environ["ADCC_DATA_DIR"] = str(_TMP)
os.environ["ADCC_DB_PATH"] = str(_TMP / "test.db")
os.environ["ADCC_UPLOAD_DIR"] = str(_TMP / "uploads")
os.environ["ADCC_PCAP_DIR"] = str(_TMP / "pcaps")
os.environ["ADCC_TOOLS_DIR"] = str(_TMP / "tools")
os.environ["ADCC_PWN_DIR"] = str(_TMP / "pwn")
os.environ["ADCC_SECRET_KEY"] = "test-secret-key"
os.environ["ADCC_LOGIN_MAX_ATTEMPTS"] = "5"

# Import after env is set.
from fastapi.testclient import TestClient  # noqa: E402

from app import db  # noqa: E402
from app.main import app  # noqa: E402

PASSWORD = "testpassword123"

_TABLES = [
    "offense_notes", "offenses", "events", "sensors", "executions", "jobs",
    "script_revisions", "scripts", "analyses", "finding_notes", "findings",
    "service_health", "services", "flags", "login_attempts", "audit_log",
    "tool_artifacts", "tools", "pwn_scripts", "pwn_cases", "scan_jobs",
    "app_config", "sessions", "users",
]


@pytest.fixture(scope="session")
def _client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def client(_client):
    # reset data and account between tests
    for t in _TABLES:
        db.execute(f"DELETE FROM {t}")
    db.execute("UPDATE account SET password_hash=NULL, totp_enabled=0, totp_secret=NULL WHERE id=1")
    _client.cookies.clear()
    return _client


@pytest.fixture
def auth(client):
    """Returns (client, headers) with the team users seeded and 'itik' logged in."""
    client.post("/api/auth/setup", json={"password": PASSWORD})
    r = client.post("/api/auth/login", json={"username": "itik", "password": PASSWORD})
    csrf = r.json()["csrf_token"]
    return client, {"X-CSRF-Token": csrf}
