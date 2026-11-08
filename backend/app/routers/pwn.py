from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from .. import auth, db
from ..config import Settings, get_settings
from ..events_bus import publish
from ..pwn import analysis, solver
from ..pwn import pwntools_utils as pu

router = APIRouter()
_require = Depends(auth.require_session)


def _case_dir(s: Settings, case_sha: str) -> Path:
    d = (s.pwn_dir / case_sha[:16]).resolve()
    if s.pwn_dir.resolve() not in d.parents:
        raise HTTPException(400, "bad path")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _bin_path(s: Settings, storage_path: str) -> Path:
    p = (s.pwn_dir / storage_path).resolve()
    if s.pwn_dir.resolve() not in p.parents:
        raise HTTPException(400, "bad path")
    return p


# ---------------- deterministic utilities (no binary needed) ----------------

class CyclicIn(BaseModel):
    length: int = Field(ge=1, le=100000)


@router.post("/cyclic")
async def cyclic(body: CyclicIn, ctx=_require):
    pat = pu.cyclic(body.length)
    return {"length": body.length, "ascii": pat.decode("latin-1"), "hex": pat.hex()}


class CyclicFindIn(BaseModel):
    value: str  # text, hex (0x..) or leaked bytes


@router.post("/cyclic-find")
async def cyclic_find(body: CyclicFindIn, ctx=_require):
    v = body.value.strip()
    if v.lower().startswith("0x"):
        off = pu.cyclic_find(int(v, 16))
    else:
        off = pu.cyclic_find(v)
    return {"offset": off, "found": off >= 0}


class PackIn(BaseModel):
    value: str
    bits: int = 64
    endian: str = Field(default="little", pattern="^(little|big)$")


@router.post("/pack")
async def pack(body: PackIn, ctx=_require):
    v = int(body.value, 0)
    hx = pu.pack(v, body.bits, body.endian)
    raw = bytes.fromhex(hx)
    return {"hex": hx, "escaped": "".join(f"\\x{b:02x}" for b in raw)}


@router.post("/unpack")
async def unpack(body: PackIn, ctx=_require):
    return {"value": pu.unpack(body.value, body.bits, body.endian), "hex_in": body.value}


# ---------------- cases ----------------

@router.post("/cases", status_code=201)
async def create_case(file: UploadFile = File(...), name: str = Form(""),
                      s: Settings = Depends(get_settings), ctx=_require):
    data = await file.read(s.max_pwn_binary_bytes + 1)
    if len(data) > s.max_pwn_binary_bytes:
        raise HTTPException(413, f"Binary exceeds {s.max_pwn_binary_bytes} bytes")
    sha = hashlib.sha256(data).hexdigest()
    fn = (file.filename or "binary").replace("/", "_").replace("\\", "_")[:120]
    d = _case_dir(s, sha)
    path = d / fn
    path.write_bytes(data)
    rel = str(path.relative_to(s.pwn_dir))
    result = analysis.analyze(data, fn, str(path))
    arch = (result.get("checksec") or {}).get("arch")
    cur = db.execute(
        "INSERT INTO pwn_cases(name, filename, size_bytes, sha256, storage_path, arch, analysis, label) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (name or fn, fn, len(data), sha, rel, arch, json.dumps(result), ctx.label),
    )
    auth.audit("pwn.upload", f"{fn} sha256={sha[:12]} arch={arch}", ctx)
    publish("pwn.changed", {"id": cur.lastrowid})
    return {"id": cur.lastrowid, "analysis": result}


@router.get("/cases")
async def list_cases(ctx=_require):
    rows = db.query("SELECT id, name, filename, arch, sha256, size_bytes, label, created_at FROM pwn_cases ORDER BY id DESC")
    return {"items": [dict(r) for r in rows]}


@router.get("/cases/{cid}")
async def get_case(cid: int, ctx=_require):
    r = db.query_one("SELECT * FROM pwn_cases WHERE id=?", (cid,))
    if not r:
        raise HTTPException(404, "Not found")
    d = dict(r)
    d["analysis"] = json.loads(d["analysis"]) if d.get("analysis") else {}
    d["scripts"] = [dict(x) for x in db.query("SELECT id, name, label, updated_at FROM pwn_scripts WHERE case_id=? ORDER BY id", (cid,))]
    return d


@router.delete("/cases/{cid}")
async def delete_case(cid: int, s: Settings = Depends(get_settings), ctx=_require):
    r = db.query_one("SELECT storage_path FROM pwn_cases WHERE id=?", (cid,))
    if r and r["storage_path"]:
        try:
            _bin_path(s, r["storage_path"]).unlink(missing_ok=True)
        except HTTPException:
            pass
    db.execute("DELETE FROM pwn_cases WHERE id=?", (cid,))
    publish("pwn.changed", {"id": cid})
    return {"ok": True}


class NotesIn(BaseModel):
    notes: str


@router.put("/cases/{cid}/notes")
async def set_notes(cid: int, body: NotesIn, ctx=_require):
    db.execute("UPDATE pwn_cases SET notes=?, updated_at=datetime('now') WHERE id=?", (body.notes, cid))
    return {"ok": True}


@router.get("/cases/{cid}/gadgets")
async def gadgets(cid: int, wanted: str | None = None, s: Settings = Depends(get_settings), ctx=_require):
    r = db.query_one("SELECT storage_path FROM pwn_cases WHERE id=?", (cid,))
    if not r:
        raise HTTPException(404, "Not found")
    data = _bin_path(s, r["storage_path"]).read_bytes()
    want = [w.strip() for w in wanted.split(",")] if wanted else None
    try:
        return pu.find_gadgets(data, want)
    except Exception as e:
        raise HTTPException(400, f"gadget search failed: {type(e).__name__}")


@router.get("/cases/{cid}/template")
async def template(cid: int, host: str = "", port: int = 0, ctx=_require):
    r = db.query_one("SELECT filename, arch FROM pwn_cases WHERE id=?", (cid,))
    if not r:
        raise HTTPException(404, "Not found")
    return {"template": pu.exploit_template(r["filename"] or "binary", r["arch"] or "amd64", host, port)}


@router.get("/cases/{cid}/solve")
async def solve(cid: int, host: str = "", port: int = 0,
                s: Settings = Depends(get_settings), ctx=_require):
    """Static solve: name the vuln, collect gadgets/addresses, estimate the
    overflow offset and generate a tailored pwntools script. Never executes."""
    r = db.query_one("SELECT filename, storage_path FROM pwn_cases WHERE id=?", (cid,))
    if not r:
        raise HTTPException(404, "Not found")
    data = _bin_path(s, r["storage_path"]).read_bytes()
    try:
        return solver.solve(data, r["filename"] or "binary", str(_bin_path(s, r["storage_path"])),
                            host=host, port=port)
    except Exception as e:  # non-ELF or malformed
        raise HTTPException(400, f"solve failed: {type(e).__name__}: {e}")


# ---------------- scripts ----------------

class ScriptIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    body: str


@router.post("/cases/{cid}/scripts", status_code=201)
async def add_script(cid: int, body: ScriptIn, ctx=_require):
    if not db.query_one("SELECT 1 FROM pwn_cases WHERE id=?", (cid,)):
        raise HTTPException(404, "Not found")
    cur = db.execute("INSERT INTO pwn_scripts(case_id, name, body, label) VALUES (?,?,?,?)",
                     (cid, body.name, body.body, ctx.label))
    publish("pwn.changed", {"id": cid})
    return {"id": cur.lastrowid}


@router.get("/scripts/{sid}")
async def get_script(sid: int, ctx=_require):
    r = db.query_one("SELECT * FROM pwn_scripts WHERE id=?", (sid,))
    if not r:
        raise HTTPException(404, "Not found")
    return dict(r)


@router.put("/scripts/{sid}")
async def update_script(sid: int, body: ScriptIn, ctx=_require):
    if not db.query_one("SELECT 1 FROM pwn_scripts WHERE id=?", (sid,)):
        raise HTTPException(404, "Not found")
    db.execute("UPDATE pwn_scripts SET name=?, body=?, updated_at=datetime('now') WHERE id=?",
               (body.name, body.body, sid))
    return {"ok": True}


@router.delete("/scripts/{sid}")
async def delete_script(sid: int, ctx=_require):
    db.execute("DELETE FROM pwn_scripts WHERE id=?", (sid,))
    return {"ok": True}


# ---------------- execution status (gated) ----------------

@router.get("/exec-status")
async def exec_status(s: Settings = Depends(get_settings), ctx=_require):
    return {
        "enabled": s.enable_pwn_exec,
        "reason": (
            "Running uploaded binaries / exploit scripts is DISABLED on the server. "
            "Uploaded binaries are untrusted; the web app only performs static analysis "
            "and template generation. Run crash/exploit tests in the dedicated local "
            "sandbox worker (scripts/pwn_sandbox.py): non-root, no network, dropped "
            "capabilities, read-only FS, CPU/mem/time limits. Enable with "
            "ADCC_ENABLE_PWN_EXEC=1 only where a sandbox is configured."
        ),
        "local_commands": {
            "run_crash": "python3 scripts/pwn_sandbox.py run ./binary < input.txt",
            "gdb": "gdb -q ./binary -ex 'run < input.txt' -ex bt",
            "test_exploit": "python3 scripts/pwn_sandbox.py exploit ./binary ./exploit.py",
        },
    }
