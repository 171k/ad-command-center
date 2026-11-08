from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from .. import auth, db
from ..analyzer import engine, project_scan
from ..analyzer.rules import RULES
from ..events_bus import publish

MAX_ZIP_BYTES = 200 * 1024 * 1024  # 200 MB project archive

router = APIRouter()
_require = Depends(auth.require_session)

MAX_CODE = 200_000  # analyze bounded input

# File extension to language, for better detection on uploads.
EXT_LANG = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".php": "php", ".java": "java",
    ".go": "go", ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".hpp": "cpp",
    ".rb": "ruby", ".sh": "shell", ".bash": "shell",
}


class AnalyzeIn(BaseModel):
    code: str = Field(min_length=1)
    language: str | None = None
    use_semgrep: bool = True


class SaveIn(BaseModel):
    title: str | None = None
    language: str | None = None
    code: str
    result: dict


@router.post("/analyze")
async def analyze(body: AnalyzeIn, ctx=_require):
    if len(body.code) > MAX_CODE:
        raise HTTPException(413, f"Code exceeds {MAX_CODE} bytes limit for analysis.")
    result = engine.analyze(body.code, body.language, body.use_semgrep)
    auth.audit("defense.analyze", f"lang={result['language']} findings={result['finding_count']}", ctx)
    return result


@router.post("/analyze-file")
async def analyze_file(
    file: UploadFile = File(...),
    language: str | None = None,
    use_semgrep: bool = True,
    ctx=_require,
):
    raw = await file.read(MAX_CODE + 1)
    if len(raw) > MAX_CODE:
        raise HTTPException(413, f"File exceeds {MAX_CODE} bytes limit for analysis.")
    if b"\x00" in raw:
        raise HTTPException(415, "Binary file detected. Upload a source-code text file.")
    try:
        code = raw.decode("utf-8")
    except UnicodeDecodeError:
        code = raw.decode("latin-1", errors="replace")
    if not code.strip():
        raise HTTPException(400, "File is empty.")
    lang = language
    if not lang and file.filename:
        lang = EXT_LANG.get(os.path.splitext(file.filename)[1].lower())
    result = engine.analyze(code, lang, use_semgrep)
    result["filename"] = file.filename
    result["source_code"] = code
    auth.audit(
        "defense.analyze_file",
        f"file={file.filename} lang={result['language']} findings={result['finding_count']}",
        ctx,
    )
    return result


@router.post("/scan", status_code=202)
async def start_scan(bg: BackgroundTasks, file: UploadFile = File(...), ctx=_require):
    """Upload a project zip. It is extracted to a sandbox, statically analyzed
    (never executed) and scanned in the background. Poll /scan/{id} for the result."""
    raw = await file.read(MAX_ZIP_BYTES + 1)
    if len(raw) > MAX_ZIP_BYTES:
        raise HTTPException(413, "Archive exceeds the 200 MB limit.")
    if raw[:2] != b"PK":
        raise HTTPException(415, "Upload a .zip archive.")
    fd, tmp = tempfile.mkstemp(prefix="adcc_zip_", suffix=".zip")
    with os.fdopen(fd, "wb") as fh:
        fh.write(raw)
    cur = db.execute(
        "INSERT INTO scan_jobs(filename, status, label) VALUES (?,?,?)",
        (file.filename, "queued", ctx.label),
    )
    job_id = cur.lastrowid
    bg.add_task(project_scan.scan_project, job_id, tmp)
    auth.audit("defense.scan", f"file={file.filename} job={job_id}", ctx)
    return {"job_id": job_id, "status": "queued"}


@router.get("/scan/{job_id}")
async def scan_status(job_id: int, ctx=_require):
    r = db.query_one("SELECT * FROM scan_jobs WHERE id=?", (job_id,))
    if not r:
        raise HTTPException(404, "Scan not found.")
    d = dict(r)
    if d.get("result"):
        d["result"] = json.loads(d["result"])
    return d


@router.get("/scans")
async def list_scans(ctx=_require):
    rows = db.query(
        "SELECT id, filename, status, phase, finding_count, total_files, scanned_files, "
        "created_at, label FROM scan_jobs ORDER BY id DESC LIMIT 50"
    )
    return {"items": [dict(r) for r in rows]}


@router.delete("/scan/{job_id}", status_code=204)
async def delete_scan(job_id: int, ctx=_require):
    r = db.query_one("SELECT id FROM scan_jobs WHERE id=?", (job_id,))
    if not r:
        raise HTTPException(404, "Scan not found.")
    db.execute("DELETE FROM scan_jobs WHERE id=?", (job_id,))
    auth.audit("defense.scan_delete", f"job={job_id}", ctx)


@router.post("/save", status_code=201)
async def save(body: SaveIn, ctx=_require):
    cur = db.execute(
        "INSERT INTO analyses(title, language, source_code, engine, result, label) "
        "VALUES (?,?,?,?,?,?)",
        (body.title, body.language, body.code, body.result.get("engine", "builtin"),
         json.dumps(body.result), ctx.label),
    )
    publish("defense.saved", {"id": cur.lastrowid})
    return {"id": cur.lastrowid}


@router.get("/analyses")
async def list_analyses(ctx=_require):
    rows = db.query("SELECT id, title, language, engine, created_at, label FROM analyses ORDER BY id DESC LIMIT 100")
    return {"items": [dict(r) for r in rows]}


@router.get("/analyses/{aid}")
async def get_analysis(aid: int, ctx=_require):
    r = db.query_one("SELECT * FROM analyses WHERE id=?", (aid,))
    if not r:
        raise HTTPException(404, "Not found")
    d = dict(r)
    d["result"] = json.loads(d["result"])
    return d


@router.get("/rules")
async def list_rules(language: str | None = None, q: str | None = None, ctx=_require):
    items = []
    for r in RULES:
        if language and language.lower() not in r.languages:
            continue
        if q and q.lower() not in (r.name + r.cwe + r.id).lower():
            continue
        items.append({"id": r.id, "name": r.name, "cwe": r.cwe, "languages": r.languages,
                      "description": r.description})
    return {"items": items, "total": len(items)}


@router.get("/rules/{rule_id}")
async def get_rule(rule_id: str, ctx=_require):
    for r in RULES:
        if r.id == rule_id:
            d = asdict(r)
            d.pop("sink", None)       # don't expose raw regex
            d.pop("flags", None)
            d.pop("safe_markers", None)
            return d
    raise HTTPException(404, "Unknown rule")
