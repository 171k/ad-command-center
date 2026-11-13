"""Tulip config control API.

GET  /api/tulip/config  — current config (any signed-in user)
GET  /api/tulip/status  — last rebuild status (any signed-in user)
POST /api/tulip/config  — validate, save, request a rebuild (admin only)

The web app only writes JSON artifacts to the shared control dir; a host-side
agent performs the actual Docker rebuild. See app/tulip_control.py.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from .. import auth, tulip_control

router = APIRouter()


@router.get("/config")
async def get_config(ctx: auth.SessionCtx = Depends(auth.require_session)):
    return {"config": tulip_control.read_config()}


@router.get("/status")
async def get_status(ctx: auth.SessionCtx = Depends(auth.require_session)):
    return tulip_control.read_status()


@router.post("/config")
async def post_config(
    payload: dict = Body(...),
    ctx: auth.SessionCtx = Depends(auth.require_admin),
):
    try:
        result = tulip_control.save_and_request_rebuild(payload, by=ctx.username or "admin")
    except tulip_control.ConfigError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    auth.audit("tulip.rebuild_requested", result["request_id"], ctx)
    return {"ok": True, **result}
