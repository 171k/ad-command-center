"""Per-user authentication, session lifecycle, CSRF, rate limiting.

Four teammates (itik, mejik, gha, namia) each have their own username and
password. Application data (findings, offenses, scripts, SIEM) is deliberately
shared — accounts exist for access control and attribution, not data isolation.

SessionCtx keeps a `.label` attribute (now the username) so the rest of the API
continues to attribute activity exactly as before.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, status

from . import db
from .config import Settings, get_settings
from .security import hash_password, needs_rehash, new_token, token_hash, verify_password

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
TEAM_USERS = ["itik", "mejik", "gha", "namia"]


def csrf_for(token: str, s: Settings) -> str:
    """Stateless CSRF token: HMAC(secret, session_hash). Survives restarts/workers."""
    return hmac.new(
        s.secret_key.encode("utf-8"), token_hash(token).encode("utf-8"), hashlib.sha256
    ).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ---------------- users ----------------

def any_user_configured() -> bool:
    row = db.query_one("SELECT COUNT(*) c FROM users WHERE password_hash IS NOT NULL AND disabled=0")
    return bool(row and row["c"])


def get_user(username: str) -> dict | None:
    row = db.query_one("SELECT * FROM users WHERE username=?", (username.strip().lower(),))
    return dict(row) if row else None


def create_user(username: str, password: str | None = None) -> int:
    username = username.strip().lower()
    ph = hash_password(password) if password else None
    cur = db.execute(
        "INSERT INTO users(username, password_hash, password_set_at) "
        "VALUES (?, ?, CASE WHEN ? IS NULL THEN NULL ELSE datetime('now') END)",
        (username, ph, ph),
    )
    return cur.lastrowid


def set_user_password(username: str, password: str) -> None:
    if len(password) < 10:
        raise ValueError("Password must be at least 10 characters.")
    db.execute(
        "UPDATE users SET password_hash=?, password_set_at=datetime('now') WHERE username=?",
        (hash_password(password), username.strip().lower()),
    )


def verify_user(username: str, password: str) -> dict | None:
    row = get_user(username)
    if not row or row.get("disabled") or not row.get("password_hash"):
        return None
    if not verify_password(row["password_hash"], password):
        return None
    if needs_rehash(row["password_hash"]):
        db.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(password), row["id"]))
    return row


# ---------------- rate limiting ----------------

def login_blocked(ip: str, s: Settings) -> bool:
    row = db.query_one(
        "SELECT COUNT(*) c FROM login_attempts "
        "WHERE success=0 AND ip=? AND at >= datetime('now', ?)",
        (ip, f"-{s.login_window_seconds} seconds"),
    )
    return bool(row and row["c"] >= s.login_max_attempts)


def record_login(ip: str, success: bool) -> None:
    db.execute("INSERT INTO login_attempts(ip, success) VALUES (?,?)", (ip, 1 if success else 0))


# ---------------- sessions ----------------

def create_session(user: dict, request: Request, s: Settings) -> tuple[str, str]:
    """Returns (session_token, csrf_token). Only hashes are persisted."""
    token = new_token()
    expires = _now() + timedelta(seconds=s.session_ttl_seconds)
    db.execute(
        "INSERT INTO sessions(id, label, user_id, expires_at, user_agent, ip) VALUES (?,?,?,?,?,?)",
        (
            token_hash(token),
            user["username"],
            user["id"],
            _iso(expires),
            (request.headers.get("user-agent") or "")[:300],
            request.client.host if request.client else None,
        ),
    )
    return token, csrf_for(token, s)


def session_from_token(token: str) -> dict | None:
    row = db.query_one(
        "SELECT * FROM sessions WHERE id=? AND revoked=0 AND expires_at > datetime('now')",
        (token_hash(token),),
    )
    return dict(row) if row else None


def touch_session(token: str, s: Settings) -> None:
    expires = _now() + timedelta(seconds=s.session_ttl_seconds)
    db.execute(
        "UPDATE sessions SET last_seen_at=datetime('now'), expires_at=? WHERE id=?",
        (_iso(expires), token_hash(token)),
    )


def revoke_session(token: str) -> None:
    db.execute("UPDATE sessions SET revoked=1 WHERE id=?", (token_hash(token),))


def revoke_all(user_id: int | None = None) -> int:
    if user_id is None:
        cur = db.execute("UPDATE sessions SET revoked=1 WHERE revoked=0")
    else:
        cur = db.execute("UPDATE sessions SET revoked=1 WHERE revoked=0 AND user_id=?", (user_id,))
    return cur.rowcount


def list_sessions() -> list[dict]:
    rows = db.query(
        "SELECT id, label, user_id, created_at, last_seen_at, expires_at, user_agent, ip "
        "FROM sessions WHERE revoked=0 AND expires_at > datetime('now') ORDER BY last_seen_at DESC"
    )
    out = []
    for r in rows:
        d = dict(r)
        d["fingerprint"] = d.pop("id")[:12]
        out.append(d)
    return out


def audit(action: str, detail: str | None, ctx: "SessionCtx | None") -> None:
    db.execute(
        "INSERT INTO audit_log(session_id, label, ip, action, detail) VALUES (?,?,?,?,?)",
        (
            (ctx.fingerprint if ctx else None),
            (ctx.label if ctx else None),
            (ctx.ip if ctx else None),
            action,
            detail,
        ),
    )


# ---------------- request-scoped auth context ----------------

class SessionCtx:
    def __init__(self, token: str, row: dict) -> None:
        self.token = token
        self.row = row
        self.fingerprint = token_hash(token)[:12]
        self.user_id = row.get("user_id")
        self.label = row.get("label")       # username — preserves attribution API
        self.username = row.get("label")
        self.ip = row.get("ip")


def _unauth() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


async def require_session(request: Request, s: Settings = Depends(get_settings)) -> SessionCtx:
    token = request.cookies.get(s.session_cookie_name)
    if not token:
        raise _unauth()
    row = session_from_token(token)
    if not row:
        raise _unauth()
    if request.method not in SAFE_METHODS:
        header = request.headers.get("x-csrf-token")
        expected = csrf_for(token, s)
        if not header or not hmac.compare_digest(header, expected):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")
    touch_session(token, s)
    return SessionCtx(token, row)
