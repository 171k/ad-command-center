"""Shared-account authentication, session lifecycle, CSRF, rate limiting.

One account (id=1). Any number of live sessions, each an opaque token stored
only as a hash. Sessions carry an optional human label ("Player 1") that is a
convenience for attributing activity in the UI — NOT a strong identity claim,
since all sessions share one credential.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, Response, status

from . import db
from .config import Settings, get_settings
import hashlib
import hmac

from .security import new_token, token_hash, verify_password, hash_password, needs_rehash

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def csrf_for(token: str, s: Settings) -> str:
    """Stateless CSRF token: HMAC(secret, session_hash). Survives restarts/workers."""
    return hmac.new(
        s.secret_key.encode("utf-8"), token_hash(token).encode("utf-8"), hashlib.sha256
    ).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ---------- account ----------

def account_is_setup() -> bool:
    row = db.query_one("SELECT password_hash FROM account WHERE id=1")
    return bool(row and row["password_hash"])


def set_password(password: str) -> None:
    if len(password) < 10:
        raise ValueError("Password must be at least 10 characters.")
    db.execute(
        "UPDATE account SET password_hash=?, password_set_at=datetime('now') WHERE id=1",
        (hash_password(password),),
    )


def verify_credentials(password: str) -> bool:
    row = db.query_one("SELECT password_hash FROM account WHERE id=1")
    if not row or not row["password_hash"]:
        return False
    ok = verify_password(row["password_hash"], password)
    if ok and needs_rehash(row["password_hash"]):
        db.execute("UPDATE account SET password_hash=? WHERE id=1", (hash_password(password),))
    return ok


# ---------- rate limiting ----------

def login_blocked(ip: str, s: Settings) -> bool:
    row = db.query_one(
        "SELECT COUNT(*) c FROM login_attempts "
        "WHERE success=0 AND ip=? AND at >= datetime('now', ?)",
        (ip, f"-{s.login_window_seconds} seconds"),
    )
    return bool(row and row["c"] >= s.login_max_attempts)


def record_login(ip: str, success: bool) -> None:
    db.execute("INSERT INTO login_attempts(ip, success) VALUES (?,?)", (ip, 1 if success else 0))


# ---------- sessions ----------

def create_session(label: str | None, request: Request, s: Settings) -> tuple[str, str]:
    """Returns (session_token, csrf_token). Only hashes are persisted."""
    token = new_token()
    expires = _now() + timedelta(seconds=s.session_ttl_seconds)
    db.execute(
        "INSERT INTO sessions(id, label, expires_at, user_agent, ip) VALUES (?,?,?,?,?)",
        (
            token_hash(token),
            label,
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


def revoke_all() -> int:
    cur = db.execute("UPDATE sessions SET revoked=1 WHERE revoked=0")
    return cur.rowcount


def list_sessions() -> list[dict]:
    rows = db.query(
        "SELECT id, label, created_at, last_seen_at, expires_at, user_agent, ip, revoked "
        "FROM sessions WHERE revoked=0 AND expires_at > datetime('now') ORDER BY last_seen_at DESC"
    )
    # never expose raw/hashed token id to client; return a short fingerprint
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


# ---------- request-scoped auth context ----------

class SessionCtx:
    def __init__(self, token: str, row: dict) -> None:
        self.token = token
        self.row = row
        self.fingerprint = token_hash(token)[:12]
        self.label = row.get("label")
        self.ip = row.get("ip")


def _unauth() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


async def require_session(
    request: Request, s: Settings = Depends(get_settings)
) -> SessionCtx:
    token = request.cookies.get(s.session_cookie_name)
    if not token:
        raise _unauth()
    row = session_from_token(token)
    if not row:
        raise _unauth()
    # CSRF for state-changing methods (double-submit)
    if request.method not in SAFE_METHODS:
        header = request.headers.get("x-csrf-token")
        expected = csrf_for(token, s)
        if not header or not hmac.compare_digest(header, expected):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")
    touch_session(token, s)
    return SessionCtx(token, row)
