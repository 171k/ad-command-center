from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import auth, db, nettools, utilsbox
from ..config import Settings, get_settings
from ..events_bus import publish
from ..runner import executor as runner_exec
from ..runner import registry as runner_registry

router = APIRouter()
_require = Depends(auth.require_session)


# ---------------- Scripts & exploit templates ----------------

class ScriptIn(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    language: str = Field(default="python", max_length=30)
    category: str = Field(default="general", max_length=40)
    body: str
    notes: str | None = None
    tags: list[str] = []
    kind: str = Field(default="script", pattern="^(script|exploit_template)$")


@router.get("/scripts")
async def list_scripts(category: str | None = None, kind: str | None = None, q: str | None = None, ctx=_require):
    where, params = [], []
    if category:
        where.append("category=?"); params.append(category)
    if kind:
        where.append("kind=?"); params.append(kind)
    if q:
        where.append("(name LIKE ? OR body LIKE ? OR notes LIKE ?)"); params += [f"%{q}%"] * 3
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    rows = db.query(f"SELECT id, name, language, category, kind, tags, label, updated_at FROM scripts {clause} ORDER BY updated_at DESC", params)
    return {"items": [dict(r) for r in rows]}


@router.get("/scripts/{sid}")
async def get_script(sid: int, ctx=_require):
    r = db.query_one("SELECT * FROM scripts WHERE id=?", (sid,))
    if not r:
        raise HTTPException(404, "Not found")
    d = dict(r)
    if d.get("tags"):
        try:
            d["tags"] = json.loads(d["tags"])
        except Exception:
            d["tags"] = []
    revs = db.query("SELECT id, note, label, created_at FROM script_revisions WHERE script_id=? ORDER BY id DESC", (sid,))
    d["revisions"] = [dict(x) for x in revs]
    return d


@router.post("/scripts", status_code=201)
async def create_script(body: ScriptIn, ctx=_require):
    cur = db.execute(
        "INSERT INTO scripts(name, language, category, body, notes, tags, kind, label) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (body.name, body.language, body.category, body.body, body.notes,
         json.dumps(body.tags), body.kind, ctx.label),
    )
    publish("scripts.changed", {"id": cur.lastrowid, "op": "create"})
    return {"id": cur.lastrowid}


@router.put("/scripts/{sid}")
async def update_script(sid: int, body: ScriptIn, ctx=_require):
    old = db.query_one("SELECT body FROM scripts WHERE id=?", (sid,))
    if not old:
        raise HTTPException(404, "Not found")
    # snapshot previous body as a revision before overwriting
    if old["body"] != body.body:
        db.execute("INSERT INTO script_revisions(script_id, body, note, label) VALUES (?,?,?,?)",
                   (sid, old["body"], "auto-snapshot before edit", ctx.label))
    db.execute(
        "UPDATE scripts SET name=?, language=?, category=?, body=?, notes=?, tags=?, kind=?, "
        "updated_at=datetime('now') WHERE id=?",
        (body.name, body.language, body.category, body.body, body.notes,
         json.dumps(body.tags), body.kind, sid),
    )
    publish("scripts.changed", {"id": sid, "op": "update"})
    return {"ok": True}


@router.post("/scripts/{sid}/duplicate", status_code=201)
async def duplicate_script(sid: int, ctx=_require):
    r = db.query_one("SELECT * FROM scripts WHERE id=?", (sid,))
    if not r:
        raise HTTPException(404, "Not found")
    cur = db.execute(
        "INSERT INTO scripts(name, language, category, body, notes, tags, kind, label) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (r["name"] + " (copy)", r["language"], r["category"], r["body"], r["notes"],
         r["tags"], r["kind"], ctx.label),
    )
    publish("scripts.changed", {"id": cur.lastrowid, "op": "create"})
    return {"id": cur.lastrowid}


@router.delete("/scripts/{sid}")
async def delete_script(sid: int, ctx=_require):
    db.execute("DELETE FROM scripts WHERE id=?", (sid,))
    publish("scripts.changed", {"id": sid, "op": "delete"})
    return {"ok": True}


# ---------------- Utilities ----------------

class UtilIn(BaseModel):
    op: str
    text: str


@router.post("/utils")
async def utils(body: UtilIn, ctx=_require):
    try:
        return utilsbox.run(body.op, body.text)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/utils/ops")
async def utils_ops(ctx=_require):
    return {"ops": list(utilsbox.OPERATIONS.keys()) + ["hashes", "jwt_decode", "timestamp"]}


# ---------------- Service health (all) ----------------

@router.post("/health/check-all")
async def check_all(ctx=_require):
    rows = db.query("SELECT * FROM services")
    results = []
    for r in rows:
        res = nettools.check_service(dict(r))
        nettools.record_health(r["id"], res)
        results.append({"id": r["id"], "name": r["name"], **res})
    publish("services.health", {"bulk": True})
    return {"results": results}


# ---------------- Jobs / execution status ----------------

@router.get("/jobs")
async def jobs(ctx=_require):
    rows = db.query("SELECT * FROM jobs ORDER BY id DESC")
    return {"items": [dict(r) for r in rows]}


@router.get("/executions")
async def executions(limit: int = 50, ctx=_require):
    rows = db.query("SELECT id, job_id, kind, status, exit_code, duration_ms, label, started_at, finished_at FROM executions ORDER BY id DESC LIMIT ?",
                    (min(max(1, limit), 200),))
    return {"items": [dict(r) for r in rows]}


@router.get("/execution-status")
async def execution_status(s: Settings = Depends(get_settings), ctx=_require):
    """Reports whether controlled task execution is available and why."""
    return {
        "task_execution_enabled": s.enable_task_execution,
        "scheduled_jobs_enabled": s.enable_scheduled_jobs,
        "https": s.cookie_secure,
        "reason": (
            "Controlled task execution is disabled by default. When enabled "
            "(ADCC_ENABLE_TASK_EXECUTION=1, recommended only behind HTTPS) it runs ONLY "
            "the fixed allowlist of local, non-target-facing utilities below — in a "
            "sandbox (no shell, scrubbed env, CPU/memory/time limits). Target-facing "
            "exploitation stays manual on Kali. The library, editor, downloads and "
            "offline utilities work regardless."
        ),
    }


# ---------------- Sandboxed local-utility runner (allowlist only) ----------------

class RunTaskIn(BaseModel):
    task_id: str = Field(max_length=64)
    args: dict = Field(default_factory=dict)


@router.get("/runner/tasks")
async def runner_tasks(s: Settings = Depends(get_settings), ctx=_require):
    return {"enabled": s.enable_task_execution, "tasks": runner_registry.task_summaries()}


@router.post("/runner/run")
async def runner_run(body: RunTaskIn, ctx=_require):
    try:
        result = runner_exec.run_task(body.task_id, body.args, ctx.label)
    except runner_exec.RunnerDisabled as e:
        raise HTTPException(403, str(e))
    except runner_exec.Busy as e:
        raise HTTPException(429, str(e))
    except runner_registry.ValidationError as e:
        raise HTTPException(400, str(e))
    auth.audit("runner.run", f"{body.task_id} -> {result['status']}", ctx)
    publish("scripts.changed", {"runner": body.task_id})
    return result
