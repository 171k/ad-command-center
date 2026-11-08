from __future__ import annotations

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from .. import auth, db
from ..config import Settings, get_settings

router = APIRouter()


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=40)
    password: str = Field(min_length=1, max_length=512)
    totp: str | None = Field(default=None, max_length=10)


class SetupBody(BaseModel):
    password: str = Field(min_length=10, max_length=512)


class PasswordBody(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10, max_length=512)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _set_session_cookies(resp: Response, token: str, csrf: str, s: Settings) -> None:
    resp.set_cookie(
        s.session_cookie_name, token, httponly=True, secure=s.cookie_secure,
        samesite=s.cookie_samesite, max_age=s.session_ttl_seconds, path="/",
    )
    resp.set_cookie(
        s.csrf_cookie_name, csrf, httponly=False, secure=s.cookie_secure,
        samesite=s.cookie_samesite, max_age=s.session_ttl_seconds, path="/",
    )


def _current_user(ctx: auth.SessionCtx) -> dict:
    user = auth.get_user(ctx.username or "")
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session user no longer exists.")
    return user


@router.get("/status")
async def status_(request: Request, s: Settings = Depends(get_settings)):
    token = request.cookies.get(s.session_cookie_name)
    row = auth.session_from_token(token) if token else None
    username = row["label"] if row else None
    totp_enabled = False
    if username:
        u = auth.get_user(username)
        totp_enabled = bool(u and u["totp_enabled"])
    return {
        "configured": auth.any_user_configured(),
        "authenticated": bool(row),
        "username": username,
        "is_admin": bool(username and username.lower() in s.admin_user_set),
        "totp_enabled": totp_enabled,
        "users": auth.TEAM_USERS,
        "app_name": s.app_name,
    }


@router.post("/setup")
async def setup(body: SetupBody, s: Settings = Depends(get_settings)):
    """First-run bootstrap: if no user has a password yet, create the team users
    all sharing the provided initial password (each can change their own later)."""
    if auth.any_user_configured():
        raise HTTPException(status.HTTP_409_CONFLICT, "Already configured. Use password rotation.")
    for name in auth.TEAM_USERS:
        if auth.get_user(name):
            auth.set_user_password(name, body.password)
        else:
            auth.create_user(name, body.password)
    auth.audit("account.setup", f"seeded {len(auth.TEAM_USERS)} users", None)
    return {"ok": True, "users": auth.TEAM_USERS}


@router.post("/login")
async def login(body: LoginBody, request: Request, response: Response, s: Settings = Depends(get_settings)):
    ip = _client_ip(request)
    if not auth.any_user_configured():
        raise HTTPException(status.HTTP_409_CONFLICT, "No accounts configured yet.")
    if auth.login_blocked(ip, s):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts. Try again later.")

    user = auth.verify_user(body.username, body.password)
    if user and user["totp_enabled"]:
        if not body.totp or not pyotp.TOTP(user["totp_secret"]).verify(body.totp, valid_window=1):
            user = None

    auth.record_login(ip, bool(user))
    if not user:
        auth.audit("login.fail", f"user={body.username.strip().lower()}", None)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password.")

    token, csrf = auth.create_session(user, request, s)
    ctx = auth.SessionCtx(token, auth.session_from_token(token) or {})
    _set_session_cookies(response, token, csrf, s)
    auth.audit("login.ok", None, ctx)
    return {"ok": True, "username": user["username"], "csrf_token": csrf}


@router.post("/logout")
async def logout(response: Response, s: Settings = Depends(get_settings),
                 ctx: auth.SessionCtx = Depends(auth.require_session)):
    auth.revoke_session(ctx.token)
    auth.audit("logout", None, ctx)
    response.delete_cookie(s.session_cookie_name, path="/")
    response.delete_cookie(s.csrf_cookie_name, path="/")
    return {"ok": True}


@router.get("/sessions")
async def sessions(ctx: auth.SessionCtx = Depends(auth.require_admin)):
    return {"sessions": auth.list_sessions(), "current": ctx.fingerprint}


@router.post("/sessions/revoke-all")
async def revoke_all(ctx: auth.SessionCtx = Depends(auth.require_admin)):
    """Admin: revoke this account's OTHER sessions."""
    n = auth.revoke_all(user_id=ctx.user_id)
    auth.audit("sessions.revoke_all", f"count={n}", ctx)
    return {"ok": True, "revoked": n}


@router.post("/password")
async def rotate_password(body: PasswordBody, ctx: auth.SessionCtx = Depends(auth.require_session)):
    user = _current_user(ctx)
    if not auth.verify_user(user["username"], body.current_password):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Current password incorrect.")
    auth.set_user_password(user["username"], body.new_password)
    n = auth.revoke_all(user_id=user["id"])  # sign out this user everywhere
    auth.audit("password.rotate", f"revoked={n}", ctx)
    return {"ok": True, "sessions_revoked": n}


# ---------- optional TOTP MFA (per user) ----------

@router.post("/totp/begin")
async def totp_begin(ctx: auth.SessionCtx = Depends(auth.require_session), s: Settings = Depends(get_settings)):
    user = _current_user(ctx)
    secret = pyotp.random_base32()
    db.execute("UPDATE users SET totp_secret=?, totp_enabled=0 WHERE id=?", (secret, user["id"]))
    uri = pyotp.TOTP(secret).provisioning_uri(name=user["username"], issuer_name=s.app_name)
    return {"provisioning_uri": uri, "secret": secret}


class TotpVerify(BaseModel):
    code: str


@router.post("/totp/enable")
async def totp_enable(body: TotpVerify, ctx: auth.SessionCtx = Depends(auth.require_session)):
    user = _current_user(ctx)
    if not user["totp_secret"] or not pyotp.TOTP(user["totp_secret"]).verify(body.code, valid_window=1):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid code.")
    db.execute("UPDATE users SET totp_enabled=1 WHERE id=?", (user["id"],))
    auth.audit("totp.enable", None, ctx)
    return {"ok": True}


@router.post("/totp/disable")
async def totp_disable(body: PasswordBody, ctx: auth.SessionCtx = Depends(auth.require_session)):
    user = _current_user(ctx)
    if not auth.verify_user(user["username"], body.current_password):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Password incorrect.")
    db.execute("UPDATE users SET totp_enabled=0, totp_secret=NULL WHERE id=?", (user["id"],))
    auth.audit("totp.disable", None, ctx)
    return {"ok": True}
