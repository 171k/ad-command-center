from __future__ import annotations

import hashlib

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import auth, db, nettools
from ..analyzer.rules import RULES
from ..config import get_settings
from ..events_bus import publish

router = APIRouter()
_require = Depends(auth.require_session)


# ---------------- Reconnaissance (scope-enforced) ----------------

class TcpIn(BaseModel):
    host: str
    port: int = Field(ge=1, le=65535)


class HttpIn(BaseModel):
    host: str
    port: int = Field(ge=1, le=65535)
    path: str = "/"
    method: str = Field(default="GET", pattern="^(GET|HEAD|POST|OPTIONS)$")
    tls: bool = False


def _scope_or_400(host, port, require_auth=True):
    try:
        return nettools.resolve_scope(host, port, require_auth)
    except nettools.ScopeError as e:
        raise HTTPException(403, str(e))


@router.post("/recon/tcp")
async def recon_tcp(body: TcpIn, ctx=_require):
    _scope_or_400(body.host, body.port)
    auth.audit("recon.tcp", f"{body.host}:{body.port}", ctx)
    return nettools.tcp_check(body.host, body.port)


@router.post("/recon/banner")
async def recon_banner(body: TcpIn, ctx=_require):
    _scope_or_400(body.host, body.port)
    auth.audit("recon.banner", f"{body.host}:{body.port}", ctx)
    return nettools.banner_grab(body.host, body.port)


@router.post("/recon/http")
async def recon_http(body: HttpIn, ctx=_require):
    _scope_or_400(body.host, body.port)
    scheme = "https" if body.tls else "http"
    path = body.path if body.path.startswith("/") else "/" + body.path
    url = f"{scheme}://{body.host}:{body.port}{path}"
    auth.audit("recon.http", url, ctx)
    return nettools.http_inspect(url, body.method)


# ---------------- Exploit knowledge library ----------------

@router.get("/knowledge")
async def knowledge(ctx=_require):
    """Technique catalog derived from the curated rule base, grouped by CWE class."""
    groups: dict[str, dict] = {}
    for r in RULES:
        key = r.cwe
        g = groups.setdefault(key, {"cwe": r.cwe, "name": r.name.split(" ")[0], "entries": []})
        g["entries"].append({
            "id": r.id, "name": r.name, "languages": r.languages,
            "description": r.description, "preconditions": r.preconditions,
            "test_procedure": r.test_procedure, "exploit_template": r.exploit_template,
            "detection": r.why, "mitigation": r.remediation, "references": r.references,
            "limitations": r.limitations,
        })
    return {"groups": list(groups.values())}


# ---------------- Flag submission utility ----------------

class FlagIn(BaseModel):
    value: str = Field(min_length=1, max_length=512)
    service_id: int | None = None


def _flag_hash(v: str) -> str:
    return hashlib.sha256(v.strip().encode()).hexdigest()


@router.post("/flags", status_code=201)
async def add_flag(body: FlagIn, ctx=_require):
    h = _flag_hash(body.value)
    existing = db.query_one("SELECT id, status FROM flags WHERE value_hash=?", (h,))
    if existing:
        return {"id": existing["id"], "status": existing["status"], "duplicate": True}
    cur = db.execute(
        "INSERT INTO flags(value_hash, value, service_id, status, label) VALUES (?,?,?,?,?)",
        (h, body.value.strip(), body.service_id, "pending", ctx.label),
    )
    # NOTE: raw flag intentionally NOT written to the audit log.
    auth.audit("flag.add", f"service={body.service_id}", ctx)
    publish("flags.changed", {"id": cur.lastrowid})
    return {"id": cur.lastrowid, "status": "pending", "duplicate": False}


@router.get("/flags")
async def list_flags(ctx=_require):
    rows = db.query("SELECT id, status, service_id, response, label, created_at, submitted_at FROM flags ORDER BY id DESC LIMIT 500")
    counts = db.query_one(
        "SELECT SUM(status='accepted') a, SUM(status='rejected') r, SUM(status='pending') p FROM flags")
    return {"items": [dict(r) for r in rows],
            "summary": {"accepted": counts["a"] or 0, "rejected": counts["r"] or 0, "pending": counts["p"] or 0}}


@router.post("/flags/submit")
async def submit_flags(ctx=_require):
    """Submit pending flags via the configured organizer adapter.

    Disabled unless an adapter is configured in app_config (keys:
    flag_submit_url, flag_submit_method, flag_submit_header_name/value,
    flag_field, flag_accept_regex). We NEVER fabricate a competition API.
    """
    cfg = {r["key"]: r["value"] for r in db.query(
        "SELECT key, value FROM app_config WHERE key LIKE 'flag_submit_%' OR key='flag_field' OR key='flag_accept_regex'")}
    url = cfg.get("flag_submit_url")
    if not url:
        raise HTTPException(409, "No flag submission adapter configured. Add flag_submit_url in Settings, "
                                 "or keep submitting manually. The competition API is not assumed.")
    import re as _re
    pending = db.query("SELECT id, value FROM flags WHERE status='pending' LIMIT 100")
    accept_re = _re.compile(cfg.get("flag_accept_regex", "accept"), _re.I)
    field = cfg.get("flag_field", "flag")
    method = (cfg.get("flag_submit_method") or "POST").upper()
    headers = {}
    if cfg.get("flag_submit_header_name"):
        headers[cfg["flag_submit_header_name"]] = cfg.get("flag_submit_header_value", "")
    results = []
    with httpx.Client(timeout=get_settings().recon_timeout_seconds) as client:
        for f in pending:
            try:
                resp = client.request(method, url, headers=headers, json={field: f["value"]})
                accepted = bool(accept_re.search(resp.text))
                status_v = "accepted" if accepted else "rejected"
                db.execute("UPDATE flags SET status=?, response=?, submitted_at=datetime('now') WHERE id=?",
                           (status_v, resp.text[:300], f["id"]))
                results.append({"id": f["id"], "status": status_v})
            except httpx.HTTPError as e:
                results.append({"id": f["id"], "status": "error", "detail": str(e)})
    auth.audit("flag.submit", f"count={len(results)}", ctx)
    publish("flags.changed", {"submitted": len(results)})
    return {"results": results}
