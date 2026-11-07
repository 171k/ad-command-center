from __future__ import annotations

from fastapi import APIRouter, Depends

from .. import auth, db
from ..config import Settings, get_settings

router = APIRouter()
_require = Depends(auth.require_session)


@router.get("/config")
async def get_config(s: Settings = Depends(get_settings), ctx=_require):
    return {
        "app_name": s.app_name,
        "environment": s.environment,
        "features": {
            "exploit_runner": s.enable_exploit_runner,
            "task_execution": s.enable_task_execution,
            "scheduled_jobs": s.enable_scheduled_jobs,
            "demo_data": s.enable_demo_data,
        },
        "limits": {
            "max_events": s.max_events,
            "event_retention_days": s.event_retention_days,
            "max_payload_display_bytes": s.max_payload_display_bytes,
            "correlation_window_seconds": s.correlation_window_seconds,
            "recon_timeout_seconds": s.recon_timeout_seconds,
        },
    }


@router.get("/audit")
async def audit_log(limit: int = 100, ctx=_require):
    rows = db.query("SELECT at, label, ip, action, detail FROM audit_log ORDER BY id DESC LIMIT ?",
                    (min(max(1, limit), 500),))
    return {"items": [dict(r) for r in rows]}


@router.get("/activity")
async def activity(limit: int = 30, ctx=_require):
    """Concise global activity feed across workspaces."""
    rows = db.query(
        "SELECT 'finding' kind, id, title label, created_at at FROM findings "
        "UNION ALL SELECT 'offense', id, category, created_at FROM offenses "
        "UNION ALL SELECT 'script', id, name, created_at FROM scripts "
        "ORDER BY at DESC LIMIT ?",
        (min(max(1, limit), 100),),
    )
    return {"items": [dict(r) for r in rows]}


@router.get("/stats")
async def stats(ctx=_require):
    def c(sql, p=()):
        r = db.query_one(sql, p)
        return r["c"] if r else 0

    return {
        "findings_open": c("SELECT COUNT(*) c FROM findings WHERE status!='resolved'"),
        "offenses_active": c("SELECT COUNT(*) c FROM offenses WHERE status IN ('new','investigating')"),
        "offenses_confirmed": c("SELECT COUNT(*) c FROM offenses WHERE outcome='confirmed'"),
        "offenses_possible": c("SELECT COUNT(*) c FROM offenses WHERE outcome='possible'"),
        "services": c("SELECT COUNT(*) c FROM services"),
        "events_total": c("SELECT COUNT(*) c FROM events"),
        "scripts": c("SELECT COUNT(*) c FROM scripts"),
    }
