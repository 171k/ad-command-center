from __future__ import annotations

import json
from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import auth, db
from ..analyzer import engine
from ..analyzer.rules import RULES
from ..events_bus import publish

router = APIRouter()
_require = Depends(auth.require_session)

MAX_CODE = 200_000  # analyze bounded input


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
