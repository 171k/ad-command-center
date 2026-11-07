from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import auth, db, nettools
from ..events_bus import publish

router = APIRouter()
_require = Depends(auth.require_session)


class ServiceIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str = Field(default="tcp", pattern="^(tcp|http|https)$")
    description: str | None = None
    owner: str = Field(default="ours", pattern="^(ours|opponent)$")
    authorized: bool = False


@router.get("")
async def list_services(ctx=_require):
    rows = db.query("SELECT * FROM services ORDER BY owner, name")
    out = []
    for r in rows:
        d = dict(r)
        h = db.query_one(
            "SELECT status, latency_ms, checked_at FROM service_health "
            "WHERE service_id=? ORDER BY id DESC LIMIT 1", (r["id"],))
        d["last_health"] = dict(h) if h else None
        out.append(d)
    return {"items": out}


@router.post("", status_code=201)
async def create_service(body: ServiceIn, ctx=_require):
    cur = db.execute(
        "INSERT INTO services(name, host, port, protocol, description, owner, authorized) "
        "VALUES (?,?,?,?,?,?,?)",
        (body.name, body.host, body.port, body.protocol, body.description, body.owner,
         1 if body.authorized else 0),
    )
    auth.audit("service.create", f"{body.host}:{body.port}", ctx)
    publish("services.changed", {"id": cur.lastrowid})
    return {"id": cur.lastrowid}


@router.put("/{sid}")
async def update_service(sid: int, body: ServiceIn, ctx=_require):
    if not db.query_one("SELECT id FROM services WHERE id=?", (sid,)):
        raise HTTPException(404, "Not found")
    db.execute(
        "UPDATE services SET name=?, host=?, port=?, protocol=?, description=?, owner=?, "
        "authorized=?, updated_at=datetime('now') WHERE id=?",
        (body.name, body.host, body.port, body.protocol, body.description, body.owner,
         1 if body.authorized else 0, sid),
    )
    auth.audit("service.update", str(sid), ctx)
    publish("services.changed", {"id": sid})
    return {"ok": True}


@router.delete("/{sid}")
async def delete_service(sid: int, ctx=_require):
    db.execute("DELETE FROM services WHERE id=?", (sid,))
    auth.audit("service.delete", str(sid), ctx)
    publish("services.changed", {"id": sid})
    return {"ok": True}


@router.post("/{sid}/check")
async def check(sid: int, ctx=_require):
    row = db.query_one("SELECT * FROM services WHERE id=?", (sid,))
    if not row:
        raise HTTPException(404, "Not found")
    result = nettools.check_service(dict(row))
    nettools.record_health(sid, result)
    publish("services.health", {"id": sid, "status": result["status"]})
    return result


@router.get("/{sid}/health")
async def health_history(sid: int, limit: int = 50, ctx=_require):
    rows = db.query(
        "SELECT status, latency_ms, detail, checked_at FROM service_health "
        "WHERE service_id=? ORDER BY id DESC LIMIT ?", (sid, min(max(1, limit), 200)))
    total = db.query_one("SELECT COUNT(*) c, SUM(status='online') up FROM service_health WHERE service_id=?", (sid,))
    uptime = (total["up"] / total["c"] * 100) if total and total["c"] else None
    return {"items": [dict(r) for r in rows], "uptime_pct": round(uptime, 1) if uptime is not None else None}
