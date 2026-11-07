from __future__ import annotations

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from .. import auth, db
from ..config import Settings, get_settings

router = APIRouter()


class LoginBody(BaseModel):
    password: str = Field(min_length=1, max_length=512)
    label: str | None = Field(default=None, max_length=40)
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
    # CSRF cookie is readable by JS (double-submit); not HttpOnly by design.
    resp.set_cookie(
        s.csrf_cookie_name, csrf, httponly=False, secure=s.cookie_secure,
        samesite=s.cookie_samesite, max_age=s.session_ttl_seconds, path="/",
    )


@router.get("/status")
async def status_(request: Request, s: Settings = Depends(get_settings)):
    token = request.cookies.get(s.session_cookie_name)
    authed = bool(token and auth.session_from_token(token))
    row = db.query_one("SELECT totp_enabled FROM account WHERE id=1")
    return {
        "account_setup": auth.account_is_setup(),
        "authenticated": authed,
        "totp_enabled": bool(row and row["totp_enabled"]),
        "app_name": s.app_name,
    }


@router.post("/setup")
async def setup(body: SetupBody, s: Settings = Depends(get_settings)):
    """One-time bootstrap: allowed only while no password is set."""
    if auth.account_is_setup():
        raise HTTPException(status.HTTP_409_CONFLICT, "Account already configured. Use password rotation.")
    auth.set_password(body.password)
    auth.audit("account.setup", "initial password set", None)
    return {"ok": True}


@router.post("/login")
async def login(body: LoginBody, request: Request, response: Response, s: Settings = Depends(get_settings)):
    ip = _client_ip(request)
    if not auth.account_is_setup():
        raise HTTPException(status.HTTP_409_CONFLICT, "Account not configured yet.")
    if auth.login_blocked(ip, s):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts. Try again later.")

    ok = auth.verify_credentials(body.password)
    # TOTP second factor when enabled
    if ok:
        row = db.query_one("SELECT totp_enabled, totp_secret FROM account WHERE id=1")
        if row and row["totp_enabled"]:
            if not body.totp or not pyotp.TOTP(row["totp_secret"]).verify(body.totp, valid_window=1):
                ok = False

    auth.record_login(ip, ok)
    if not ok:
        auth.audit("login.fail", None, None)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials.")

    token, csrf = auth.create_session(body.label, request, s)
    _set_session_cookies(response, token, csrf, s)
    ctx = auth.SessionCtx(token, auth.session_from_token(token) or {})
    auth.audit("login.ok", f"label={body.label}", ctx)
    return {"ok": True, "label": body.label, "csrf_token": csrf}


@router.post("/logout")
async def logout(request: Request, response: Response, s: Settings = Depends(get_settings),
                 ctx: auth.SessionCtx = Depends(auth.require_session)):
    auth.revoke_session(ctx.token)
    auth.audit("logout", None, ctx)
    response.delete_cookie(s.session_cookie_name, path="/")
    response.delete_cookie(s.csrf_cookie_name, path="/")
    return {"ok": True}


@router.get("/sessions")
async def sessions(ctx: auth.SessionCtx = Depends(auth.require_session)):
    return {"sessions": auth.list_sessions(), "current": ctx.fingerprint}


@router.post("/sessions/revoke-all")
async def revoke_all(ctx: auth.SessionCtx = Depends(auth.require_session)):
    n = auth.revoke_all()
    auth.audit("sessions.revoke_all", f"count={n}", ctx)
    return {"ok": True, "revoked": n}


@router.post("/password")
async def rotate_password(body: PasswordBody, ctx: auth.SessionCtx = Depends(auth.require_session)):
    if not auth.verify_credentials(body.current_password):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Current password incorrect.")
    auth.set_password(body.new_password)
    n = auth.revoke_all()  # force re-login everywhere after a password change
    auth.audit("password.rotate", f"revoked={n}", ctx)
    return {"ok": True, "sessions_revoked": n}


# ---------- optional TOTP MFA ----------

@router.post("/totp/begin")
async def totp_begin(ctx: auth.SessionCtx = Depends(auth.require_session), s: Settings = Depends(get_settings)):
    secret = pyotp.random_base32()
    db.execute("UPDATE account SET totp_secret=?, totp_enabled=0 WHERE id=1", (secret,))
    uri = pyotp.TOTP(secret).provisioning_uri(name="team", issuer_name=s.app_name)
    return {"provisioning_uri": uri, "secret": secret}


class TotpVerify(BaseModel):
    code: str


@router.post("/totp/enable")
async def totp_enable(body: TotpVerify, ctx: auth.SessionCtx = Depends(auth.require_session)):
    row = db.query_one("SELECT totp_secret FROM account WHERE id=1")
    if not row or not row["totp_secret"] or not pyotp.TOTP(row["totp_secret"]).verify(body.code, valid_window=1):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid code.")
    db.execute("UPDATE account SET totp_enabled=1 WHERE id=1")
    auth.audit("totp.enable", None, ctx)
    return {"ok": True}


@router.post("/totp/disable")
async def totp_disable(body: PasswordBody, ctx: auth.SessionCtx = Depends(auth.require_session)):
    if not auth.verify_credentials(body.current_password):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Password incorrect.")
    db.execute("UPDATE account SET totp_enabled=0, totp_secret=NULL WHERE id=1")
    auth.audit("totp.disable", None, ctx)
    return {"ok": True}
