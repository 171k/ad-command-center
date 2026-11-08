"""Operations endpoints: curated guides + deterministic generators.

Guides are read-only reference content. Generators format editable scripts and
commands; they never execute anything. Target authorisation for the RCE generator
is enforced here against the registered authorised scope (server-side).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import auth, db
from ..ops import generators, guides

router = APIRouter()
_require = Depends(auth.require_session)


@router.get("/guides")
async def list_guides(q: str | None = None, ctx=_require):
    return {"items": guides.search_guides(q or "")}


@router.get("/guides/{gid}")
async def get_guide(gid: str, ctx=_require):
    g = guides.get_guide(gid)
    if not g:
        raise HTTPException(404, "Guide not found.")
    return g


class RceSpec(BaseModel):
    protocol: str = "requests"
    name: str | None = None
    host: str = Field(min_length=1, max_length=253)
    port: int | None = Field(default=None, ge=1, le=65535)
    tls: bool = False
    path: str = "/"
    method: str = "GET"
    headers: dict = Field(default_factory=dict)
    params: dict = Field(default_factory=dict)
    body: str = ""
    payload: str = ""
    expected: str = ""
    timeout: int = Field(default=10, ge=1, le=120)


def _host_is_authorised(host: str) -> bool:
    """Server-side scope check: the host must be a registered, authorised target."""
    host = (host or "").strip().lower()
    rows = db.query("SELECT host FROM services WHERE authorized=1")
    allowed = {str(r["host"]).strip().lower() for r in rows}
    return host in allowed


@router.post("/rce-template")
async def rce_template(spec: RceSpec, ctx=_require):
    if not _host_is_authorised(spec.host):
        raise HTTPException(
            403, "Target is not a registered authorised service. Add it in Attack -> "
                 "Targets and mark it authorised first.")
    try:
        out = generators.rce_script(spec.model_dump())
    except ValueError as e:
        raise HTTPException(400, str(e))
    auth.audit("attack.rce_template", f"proto={spec.protocol} host={spec.host}", ctx)
    return out


class TcpdumpSpec(BaseModel):
    interface: str = "<IFACE>"
    ports: list[int] = Field(default_factory=list)
    protocol: str = ""
    hosts: list[str] = Field(default_factory=list)
    exclude_ssh: bool = True
    snaplen: int = Field(default=0, ge=0, le=262144)
    rotate_seconds: int = Field(default=30, ge=0, le=86400)
    rotate_mb: int = Field(default=0, ge=0, le=10000)
    keep_files: int = Field(default=60, ge=0, le=100000)
    out_dir: str = "./captures"
    out_prefix: str = "cap"


@router.post("/tcpdump")
async def tcpdump(spec: TcpdumpSpec, ctx=_require):
    return generators.tcpdump_command(spec.model_dump())
