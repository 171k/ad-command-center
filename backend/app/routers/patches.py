"""Defense patch management: create a proposed patch for a finding, review it,
record security + functional validation separately, and track its lifecycle.

No user code is executed. Status transitions are validated server-side and every
write is guarded by an optimistic-lock `version` so concurrent teammates cannot
silently overwrite each other.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from .. import auth, db, patching
from ..events_bus import publish

router = APIRouter()
_require = Depends(auth.require_session)

MAX_CODE = 200_000


class PatchIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    service_id: int | None = None
    finding_id: str | None = None
    cwe: str | None = None
    filename: str | None = None
    affected_lines: str | None = None
    language: str | None = None
    original_code: str = Field(default="", max_length=MAX_CODE)
    patched_code: str = Field(default="", max_length=MAX_CODE)
    notes: str | None = None


class PatchEdit(BaseModel):
    version: int
    title: str | None = None
    original_code: str | None = Field(default=None, max_length=MAX_CODE)
    patched_code: str | None = Field(default=None, max_length=MAX_CODE)
    filename: str | None = None
    affected_lines: str | None = None
    rollback_ref: str | None = None
    notes: str | None = None


class StatusIn(BaseModel):
    version: int
    to_status: str
    reviewer: str | None = None
    note: str | None = None


class ValidationIn(BaseModel):
    version: int
    kind: str  # "security" | "functional"
    result: str  # pending|pass|fail|na
    notes: str | None = None


def _get(pid: int) -> dict:
    r = db.query_one("SELECT * FROM patches WHERE id=?", (pid,))
    if not r:
        raise HTTPException(404, "Patch not found.")
    return dict(r)


def _check_version(patch: dict, version: int):
    if int(patch["version"]) != int(version):
        raise HTTPException(409, "This patch changed since you loaded it (a teammate edited it). "
                                 "Reload and reapply your change.")


def _event(pid: int, kind: str, detail: str, ctx):
    db.execute("INSERT INTO patch_events(patch_id, kind, detail, label) VALUES (?,?,?,?)",
               (pid, kind, detail, ctx.label))


def _bump(pid: int):
    db.execute("UPDATE patches SET version=version+1, updated_at=strftime('%Y-%m-%d %H:%M:%S','now') WHERE id=?", (pid,))


@router.post("", status_code=201)
async def create_patch(body: PatchIn, ctx=_require):
    cur = db.execute(
        "INSERT INTO patches(title, service_id, finding_id, cwe, filename, affected_lines, "
        "language, original_code, patched_code, notes, label) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (body.title, body.service_id, body.finding_id, body.cwe, body.filename, body.affected_lines,
         body.language, body.original_code, body.patched_code, body.notes, ctx.label),
    )
    pid = cur.lastrowid
    _event(pid, "status", "created as suggested", ctx)
    auth.audit("defense.patch_create", f"id={pid} cwe={body.cwe}", ctx)
    publish("patch.changed", {"id": pid})
    return {"id": pid}


@router.get("")
async def list_patches(status: str | None = None, ctx=_require):
    q = ("SELECT id, title, service_id, finding_id, cwe, filename, status, reviewer, "
         "security_status, functional_status, deployment_status, version, label, "
         "created_at, updated_at FROM patches")
    params: tuple = ()
    if status:
        q += " WHERE status=?"
        params = (status,)
    q += " ORDER BY id DESC LIMIT 200"
    return {"items": [dict(r) for r in db.query(q, params)]}


@router.get("/{pid}")
async def get_patch(pid: int, ctx=_require):
    p = _get(pid)
    p["unified_diff"] = patching.unified_diff(p["original_code"], p["patched_code"], p.get("filename") or "patch")
    p["side_by_side"] = patching.side_by_side(p["original_code"], p["patched_code"])
    p["diff_stats"] = patching.diff_stats(p["original_code"], p["patched_code"])
    p["allowed_transitions"] = sorted(patching.TRANSITIONS.get(p["status"], set()))
    p["events"] = [dict(r) for r in db.query(
        "SELECT kind, detail, label, at FROM patch_events WHERE patch_id=? ORDER BY id DESC LIMIT 100", (pid,))]
    return p


@router.put("/{pid}")
async def edit_patch(pid: int, body: PatchEdit, ctx=_require):
    p = _get(pid)
    _check_version(p, body.version)
    fields = {k: v for k, v in body.model_dump(exclude={"version"}).items() if v is not None}
    if fields:
        sets = ", ".join(f"{k}=?" for k in fields)
        db.execute(f"UPDATE patches SET {sets} WHERE id=?", (*fields.values(), pid))
    _bump(pid)
    _event(pid, "note", "edited " + ", ".join(fields) if fields else "edited", ctx)
    publish("patch.changed", {"id": pid})
    return await get_patch(pid, ctx)


@router.post("/{pid}/status")
async def set_status(pid: int, body: StatusIn, ctx=_require):
    p = _get(pid)
    _check_version(p, body.version)
    err = patching.transition_error(p["status"], body.to_status, p)
    if err:
        raise HTTPException(400, err)
    deploy = patching.deployment_status_for(body.to_status, p["deployment_status"])
    db.execute("UPDATE patches SET status=?, deployment_status=?, reviewer=COALESCE(?, reviewer) WHERE id=?",
               (body.to_status, deploy, body.reviewer, pid))
    _bump(pid)
    detail = f"{p['status']} -> {body.to_status}" + (f" ({body.note})" if body.note else "")
    _event(pid, "status", detail, ctx)
    auth.audit("defense.patch_status", f"id={pid} {detail}", ctx)
    publish("patch.changed", {"id": pid})
    return await get_patch(pid, ctx)


@router.post("/{pid}/validation")
async def record_validation(pid: int, body: ValidationIn, ctx=_require):
    p = _get(pid)
    _check_version(p, body.version)
    if body.kind not in ("security", "functional"):
        raise HTTPException(400, "kind must be 'security' or 'functional'.")
    if body.result not in patching.VALIDATION_STATUSES:
        raise HTTPException(400, f"result must be one of {sorted(patching.VALIDATION_STATUSES)}.")
    col_status = f"{body.kind}_status"
    col_notes = f"{body.kind}_notes"
    db.execute(f"UPDATE patches SET {col_status}=?, {col_notes}=? WHERE id=?",
               (body.result, body.notes, pid))
    _bump(pid)
    _event(pid, "validation", f"{body.kind}={body.result}" + (f" ({body.notes})" if body.notes else ""), ctx)
    publish("patch.changed", {"id": pid})
    return await get_patch(pid, ctx)


@router.get("/{pid}/export")
async def export_patch(pid: int, ctx=_require):
    p = _get(pid)
    diff = patching.unified_diff(p["original_code"], p["patched_code"], p.get("filename") or "patch")
    fn = (p.get("filename") or f"patch-{pid}").replace("/", "_") + ".diff"
    return Response(content=diff + "\n", media_type="text/x-diff",
                    headers={"Content-Disposition": f'attachment; filename="{fn}"'})


@router.delete("/{pid}", status_code=204)
async def delete_patch(pid: int, ctx=_require):
    _get(pid)
    db.execute("DELETE FROM patches WHERE id=?", (pid,))
    auth.audit("defense.patch_delete", f"id={pid}", ctx)
    publish("patch.changed", {"id": pid})
