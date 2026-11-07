from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .. import auth, db
from ..events_bus import publish

router = APIRouter()
_require = Depends(auth.require_session)


class FindingIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str | None = None
    category: str | None = None
    source: str | None = None
    service_id: int | None = None
    severity: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    status: str = Field(default="open", pattern="^(open|investigating|resolved)$")
    evidence: dict | list | None = None
    refs: dict | list | None = None
    label: str | None = Field(default=None, max_length=40)


class NoteIn(BaseModel):
    body: str = Field(min_length=1)
    label: str | None = Field(default=None, max_length=40)


def _row_to_finding(r) -> dict:
    d = dict(r)
    for k in ("evidence", "refs"):
        if d.get(k):
            try:
                d[k] = json.loads(d[k])
            except Exception:
                pass
    return d


@router.get("")
async def list_findings(
    status: str | None = None, category: str | None = None, q: str | None = None,
    page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200), ctx=_require,
):
    where, params = [], []
    if status:
        where.append("status=?"); params.append(status)
    if category:
        where.append("category=?"); params.append(category)
    if q:
        where.append("(title LIKE ? OR description LIKE ?)"); params += [f"%{q}%", f"%{q}%"]
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    total = db.query_one(f"SELECT COUNT(*) c FROM findings {clause}", params)["c"]
    rows = db.query(
        f"SELECT * FROM findings {clause} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
        params + [size, (page - 1) * size])
    return {"items": [_row_to_finding(r) for r in rows], "total": total, "page": page, "size": size}


@router.get("/{fid}")
async def get_finding(fid: int, ctx=_require):
    r = db.query_one("SELECT * FROM findings WHERE id=?", (fid,))
    if not r:
        raise HTTPException(404, "Not found")
    notes = db.query("SELECT * FROM finding_notes WHERE finding_id=? ORDER BY id", (fid,))
    d = _row_to_finding(r)
    d["notes"] = [dict(n) for n in notes]
    return d


@router.post("", status_code=201)
async def create_finding(body: FindingIn, ctx=_require):
    cur = db.execute(
        "INSERT INTO findings(title, description, category, source, service_id, severity, "
        "status, evidence, refs, label) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (body.title, body.description, body.category, body.source, body.service_id,
         body.severity, body.status,
         json.dumps(body.evidence) if body.evidence is not None else None,
         json.dumps(body.refs) if body.refs is not None else None, body.label or ctx.label),
    )
    auth.audit("finding.create", body.title, ctx)
    publish("findings.changed", {"id": cur.lastrowid, "op": "create"})
    return {"id": cur.lastrowid}


@router.put("/{fid}")
async def update_finding(fid: int, body: FindingIn, ctx=_require):
    if not db.query_one("SELECT id FROM findings WHERE id=?", (fid,)):
        raise HTTPException(404, "Not found")
    db.execute(
        "UPDATE findings SET title=?, description=?, category=?, source=?, service_id=?, "
        "severity=?, status=?, evidence=?, refs=?, updated_at=datetime('now') WHERE id=?",
        (body.title, body.description, body.category, body.source, body.service_id,
         body.severity, body.status,
         json.dumps(body.evidence) if body.evidence is not None else None,
         json.dumps(body.refs) if body.refs is not None else None, fid),
    )
    auth.audit("finding.update", str(fid), ctx)
    publish("findings.changed", {"id": fid, "op": "update"})
    return {"ok": True}


@router.delete("/{fid}")
async def delete_finding(fid: int, ctx=_require):
    db.execute("DELETE FROM findings WHERE id=?", (fid,))
    auth.audit("finding.delete", str(fid), ctx)
    publish("findings.changed", {"id": fid, "op": "delete"})
    return {"ok": True}


@router.post("/{fid}/notes", status_code=201)
async def add_note(fid: int, body: NoteIn, ctx=_require):
    if not db.query_one("SELECT id FROM findings WHERE id=?", (fid,)):
        raise HTTPException(404, "Not found")
    cur = db.execute("INSERT INTO finding_notes(finding_id, body, label) VALUES (?,?,?)",
                     (fid, body.body, body.label or ctx.label))
    db.execute("UPDATE findings SET updated_at=datetime('now') WHERE id=?", (fid,))
    publish("findings.changed", {"id": fid, "op": "note"})
    return {"id": cur.lastrowid}
