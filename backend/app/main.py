"""A&D Command Center API entrypoint."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import StreamingResponse

from . import db, events_bus
from .auth import SessionCtx, require_session
from .config import get_settings
from .routers import (
    attack, automation, auth_router, defense, findings, ops, patches, pwn, services, soc,
    system, tools, tulip_control,
)
from .tools import catalog_seed

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    applied = db.run_migrations()
    app.state.migrations_applied = applied
    try:
        catalog_seed.seed_catalog()  # populate tool catalog metadata if empty
    except Exception:
        pass
    yield


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

# Host allowlist (defense in depth; Caddy already restricts which hosts reach us).
# "*" disables it (default, e.g. tests/dev). In production set ADCC_ALLOWED_HOSTS.
if settings.allowed_hosts.strip() != "*":
    _hosts = [h.strip() for h in settings.allowed_hosts.split(",") if h.strip()]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=_hosts)

# In dev the Vite frontend runs on a separate origin and needs credentialed CORS.
if not settings.is_production:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Restrictive CSP for the API; the SPA is served separately and sets its own.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    )
    if settings.is_production:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


api = app  # alias

app.include_router(auth_router.router, prefix="/api/auth", tags=["auth"])
app.include_router(system.router, prefix="/api/system", tags=["system"])
app.include_router(services.router, prefix="/api/services", tags=["services"])
app.include_router(findings.router, prefix="/api/findings", tags=["findings"])
app.include_router(attack.router, prefix="/api/attack", tags=["attack"])
app.include_router(defense.router, prefix="/api/defense", tags=["defense"])
app.include_router(automation.router, prefix="/api/automation", tags=["automation"])
app.include_router(soc.router, prefix="/api/soc", tags=["soc"])
app.include_router(tools.router, prefix="/api/tools", tags=["tools"])
app.include_router(tulip_control.router, prefix="/api/tulip", tags=["tulip"])
app.include_router(pwn.router, prefix="/api/pwn", tags=["pwn"])
app.include_router(ops.router, prefix="/api/ops", tags=["ops"])
app.include_router(patches.router, prefix="/api/patches", tags=["patches"])


@app.get("/api/health")
async def health():
    row = db.query_one("SELECT COUNT(*) c FROM sessions")
    return {"status": "ok", "db": "ok" if row is not None else "error",
            "subscribers": events_bus.subscriber_count()}


@app.get("/api/stream")
async def stream(request: Request, ctx: SessionCtx = Depends(require_session)):
    """Server-Sent Events: live cross-session updates (findings, offenses, …)."""
    q = await events_bus.subscribe()

    async def gen():
        try:
            yield "event: ping\ndata: {}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=20.0)
                    yield f"data: {msg}\n\n"
                except asyncio.TimeoutError:
                    yield "event: ping\ndata: {}\n\n"
        finally:
            events_bus.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
