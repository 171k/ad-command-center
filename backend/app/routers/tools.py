from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from .. import auth, db
from ..config import Settings, get_settings
from ..events_bus import publish
from ..tools import catalog_seed, repository as repo

router = APIRouter()
_require = Depends(auth.require_session)

_ADTOOLS = Path(__file__).resolve().parent.parent / "tools" / "adtools_cli.py"


class ToolIn(BaseModel):
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    name: str = Field(min_length=1, max_length=120)
    category: str = Field(min_length=1, max_length=60)
    version: str | None = None
    description: str | None = None
    license: str | None = None
    provenance: str | None = None
    os_support: list[str] = []
    dependencies: list[str] = []
    install: dict = {}
    tags: list[str] = []


@router.get("")
async def list_tools(q: str | None = None, category: str | None = None, ctx=_require):
    where, params = [], []
    if category:
        where.append("category=?"); params.append(category)
    if q:
        where.append("(name LIKE ? OR slug LIKE ? OR description LIKE ? OR tags LIKE ?)")
        params += [f"%{q}%"] * 4
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    rows = db.query(f"SELECT * FROM tools {clause} ORDER BY category, name", params)
    out = []
    for r in rows:
        d = repo.tool_to_dict(dict(r))
        cnt = db.query_one("SELECT COUNT(*) c FROM tool_artifacts WHERE tool_id=?", (r["id"],))["c"]
        d["artifact_count"] = cnt
        out.append(d)
    cats = [row["category"] for row in db.query("SELECT DISTINCT category FROM tools ORDER BY category")]
    return {"items": out, "categories": cats, "total": len(out)}


@router.get("/manifest")
async def manifest(ctx=_require):
    return repo.manifest()


@router.get("/adtools")
async def adtools_cli(ctx=_require):
    """Serve the adtools CLI script (install without GitHub)."""
    src = _ADTOOLS.read_text(encoding="utf-8") if _ADTOOLS.exists() else "# adtools CLI not found"
    return PlainTextResponse(src, headers={"Content-Disposition": "attachment; filename=adtools.py"})


@router.get("/export/bundle")
async def export_bundle(ctx=_require):
    """Full offline bundle: every hosted artifact + manifest + adtools + README."""
    src = _ADTOOLS.read_text(encoding="utf-8") if _ADTOOLS.exists() else ""
    readme = _BUNDLE_README
    data = repo.build_offline_bundle(src, readme)
    auth.audit("tools.export", f"bytes={len(data)}", ctx)
    return Response(
        content=data, media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=adcc-tool-bundle.zip"},
    )


@router.post("/seed")
async def seed(ctx=_require):
    n = catalog_seed.seed_catalog()
    publish("tools.changed", {"seeded": n})
    return {"seeded": n}


@router.get("/{slug}")
async def get_tool(slug: str, ctx=_require):
    r = db.query_one("SELECT * FROM tools WHERE slug=?", (slug,))
    if not r:
        raise HTTPException(404, "Unknown tool")
    return repo.tool_to_dict(dict(r), with_artifacts=True)


@router.post("", status_code=201)
async def upsert_tool(body: ToolIn, ctx=_require):
    existing = db.query_one("SELECT id FROM tools WHERE slug=?", (body.slug,))
    args = (body.name, body.category, body.version, body.description, body.license, body.provenance,
            json.dumps(body.os_support), json.dumps(body.dependencies), json.dumps(body.install),
            json.dumps(body.tags))
    if existing:
        db.execute("UPDATE tools SET name=?, category=?, version=?, description=?, license=?, provenance=?, "
                   "os_support=?, dependencies=?, install=?, tags=?, updated_at=datetime('now') WHERE slug=?",
                   args + (body.slug,))
        tid = existing["id"]
    else:
        cur = db.execute("INSERT INTO tools(name,category,version,description,license,provenance,"
                         "os_support,dependencies,install,tags,slug) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                         args + (body.slug,))
        tid = cur.lastrowid
    auth.audit("tools.upsert", body.slug, ctx)
    publish("tools.changed", {"slug": body.slug})
    return {"id": tid, "slug": body.slug}


@router.delete("/{slug}")
async def delete_tool(slug: str, ctx=_require):
    row = db.query_one("SELECT id FROM tools WHERE slug=?", (slug,))
    if not row:
        raise HTTPException(404, "Unknown tool")
    # remove artifact files
    for a in db.query("SELECT storage_path FROM tool_artifacts WHERE tool_id=?", (row["id"],)):
        try:
            repo.artifact_abspath(a["storage_path"]).unlink(missing_ok=True)
        except ValueError:
            pass
    db.execute("DELETE FROM tools WHERE id=?", (row["id"],))
    auth.audit("tools.delete", slug, ctx)
    publish("tools.changed", {"slug": slug})
    return {"ok": True}


@router.post("/{slug}/artifacts", status_code=201)
async def upload_artifact(slug: str, file: UploadFile = File(...), os: str = Form("any"),
                          arch: str = Form("any"), notes: str = Form(""),
                          s: Settings = Depends(get_settings), ctx=_require):
    tool = db.query_one("SELECT id FROM tools WHERE slug=?", (slug,))
    if not tool:
        raise HTTPException(404, "Unknown tool")
    data = await file.read(s.max_tool_artifact_bytes + 1)
    if len(data) > s.max_tool_artifact_bytes:
        raise HTTPException(413, f"Artifact exceeds {s.max_tool_artifact_bytes} bytes")
    try:
        meta = repo.save_artifact(slug, file.filename or "artifact", data)
    except ValueError as e:
        raise HTTPException(400, str(e))
    cur = db.execute(
        "INSERT INTO tool_artifacts(tool_id, filename, os, arch, size_bytes, sha256, storage_path, notes) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (tool["id"], meta["filename"], os, arch, meta["size_bytes"], meta["sha256"], meta["storage_path"], notes),
    )
    auth.audit("tools.artifact.upload", f"{slug}/{meta['filename']} sha256={meta['sha256'][:12]}", ctx)
    publish("tools.changed", {"slug": slug})
    return {"id": cur.lastrowid, **meta}


@router.get("/{slug}/artifacts/{aid}/download")
async def download_artifact(slug: str, aid: int, ctx=_require):
    row = db.query_one(
        "SELECT a.* FROM tool_artifacts a JOIN tools t ON t.id=a.tool_id WHERE t.slug=? AND a.id=?",
        (slug, aid))
    if not row:
        raise HTTPException(404, "Unknown artifact")
    try:
        path = repo.artifact_abspath(row["storage_path"])
    except ValueError:
        raise HTTPException(500, "storage error")
    if not path.exists():
        raise HTTPException(410, "Artifact file missing on server")
    auth.audit("tools.artifact.download", f"{slug}/{row['filename']}", ctx)
    return FileResponse(
        path, filename=row["filename"], media_type="application/octet-stream",
        headers={"X-Checksum-SHA256": row["sha256"], "X-Artifact-Size": str(row["size_bytes"])},
    )


@router.get("/{slug}/artifacts/{aid}/verify")
async def verify_artifact(slug: str, aid: int, ctx=_require):
    row = db.query_one(
        "SELECT a.* FROM tool_artifacts a JOIN tools t ON t.id=a.tool_id WHERE t.slug=? AND a.id=?",
        (slug, aid))
    if not row:
        raise HTTPException(404, "Unknown artifact")
    return repo.verify_artifact(dict(row))


@router.delete("/{slug}/artifacts/{aid}")
async def delete_artifact(slug: str, aid: int, ctx=_require):
    row = db.query_one(
        "SELECT a.* FROM tool_artifacts a JOIN tools t ON t.id=a.tool_id WHERE t.slug=? AND a.id=?",
        (slug, aid))
    if not row:
        raise HTTPException(404, "Unknown artifact")
    try:
        repo.artifact_abspath(row["storage_path"]).unlink(missing_ok=True)
    except ValueError:
        pass
    db.execute("DELETE FROM tool_artifacts WHERE id=?", (aid,))
    auth.audit("tools.artifact.delete", f"{slug}/{row['filename']}", ctx)
    publish("tools.changed", {"slug": slug})
    return {"ok": True}


_BUNDLE_README = """# A&D Command Center, Offline Tool Bundle

This bundle lets you install the team's approved tools with NO network and NO
GitHub access.

Contents:
  manifest.json   catalog + per-artifact SHA-256 checksums
  artifacts/      the hosted tool files
  adtools.py      offline-capable CLI

Usage (offline):
  python3 adtools.py --offline list
  python3 adtools.py --offline verify <tool-slug>
  python3 adtools.py --offline install <tool-slug>     # verifies checksum, then places the file

Every file is verified against manifest.json's SHA-256 before use. Review each
tool's license (shown by `adtools info <slug>`) before distributing.
"""
