from __future__ import annotations

import base64
import json

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from .. import auth, db
from ..config import Settings, get_settings
from ..events_bus import publish
from ..security import new_token, token_hash
from ..soc import normalize
from ..soc.classify import classify
from ..soc.correlate import ingest_batch
from ..soc.normalize import TECHNIQUE_PATTERNS

router = APIRouter()
_require = Depends(auth.require_session)


# ---------------- Ingestion ----------------

class IngestIn(BaseModel):
    events: list[dict] = Field(default_factory=list)       # Suricata EVE records
    access_logs: list[dict] = Field(default_factory=list)  # structured HTTP rows


def _normalize_all(body: IngestIn) -> list[tuple[dict, dict]]:
    items: list[tuple[dict, dict]] = []
    for rec in body.events:
        ev = normalize.from_eve(rec)
        if ev:
            items.append((ev, rec))
    for row in body.access_logs:
        items.append((normalize.from_access_log(row), row))
    return items


@router.post("/ingest")
async def ingest(body: IngestIn, s: Settings = Depends(get_settings), ctx=_require):
    items = _normalize_all(body)
    if len(items) > s.ingest_queue_max:
        items = items[: s.ingest_queue_max]
    if not items:
        return {"ingested": 0, "note": "No parsable records."}
    summary = ingest_batch(items)
    _record_ingest_health(len(items))
    _enforce_retention(s)
    return summary


async def _sensor_from_token(authorization: str | None) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Sensor token required (Authorization: Bearer ...).")
    tok = authorization.split(" ", 1)[1].strip()
    row = db.query_one("SELECT * FROM sensors WHERE token_hash=? AND enabled=1", (token_hash(tok),))
    if not row:
        raise HTTPException(401, "Invalid or disabled sensor token.")
    db.execute("UPDATE sensors SET last_seen=datetime('now') WHERE id=?", (row["id"],))
    return dict(row)


@router.post("/ingest/sensor")
async def ingest_sensor(request: Request, authorization: str | None = Header(default=None),
                        s: Settings = Depends(get_settings)):
    """Authenticated collector ingestion. Scoped token; no session, no admin rights."""
    sensor = await _sensor_from_token(authorization)
    raw = (await request.body()).decode("utf-8", "replace")
    records: list[dict] = []
    raw = raw.strip()
    if raw.startswith("["):
        try:
            records = json.loads(raw)
        except json.JSONDecodeError:
            raise HTTPException(400, "Invalid JSON array.")
    else:  # NDJSON (EVE default)
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # skip malformed records safely
    items = []
    for rec in records[: s.ingest_queue_max]:
        ev = normalize.from_eve(rec)
        if ev:
            ev["sensor_id"] = sensor["id"]
            items.append((ev, rec))
    if not items:
        return {"ingested": 0, "note": "No parsable EVE records."}
    summary = ingest_batch(items)
    _record_ingest_health(len(items))
    _enforce_retention(s)
    return summary


def _record_ingest_health(n: int) -> None:
    db.execute("INSERT OR REPLACE INTO app_config(key, value, updated_at) VALUES ('soc_last_ingest', ?, datetime('now'))",
               (json.dumps({"count": n}),))


def _enforce_retention(s: Settings) -> None:
    db.execute("DELETE FROM events WHERE ts < datetime('now', ?)", (f"-{s.event_retention_days} days",))
    over = db.query_one("SELECT COUNT(*) c FROM events")
    if over and over["c"] > s.max_events:
        excess = over["c"] - s.max_events
        db.execute("DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id ASC LIMIT ?)", (excess,))


# ---------------- Dashboard ----------------

@router.get("/dashboard")
async def dashboard(ctx=_require):
    def one(sql, p=()):
        r = db.query_one(sql, p)
        return dict(r) if r else {}

    confirmed = one("SELECT COUNT(*) c FROM offenses WHERE outcome='confirmed' AND status!='suppressed'")["c"]
    possible = one("SELECT COUNT(*) c FROM offenses WHERE outcome='possible' AND status!='suppressed'")["c"]
    active = one("SELECT COUNT(*) c FROM offenses WHERE status IN ('new','investigating')")["c"]
    blocked = one("SELECT COUNT(*) c FROM offenses WHERE outcome='blocked'")["c"]
    events_total = one("SELECT COUNT(*) c FROM events")["c"]
    last_ingest = db.query_one("SELECT value, updated_at FROM app_config WHERE key='soc_last_ingest'")
    recent = db.query(
        "SELECT category, COUNT(*) c FROM events WHERE ts >= datetime('now','-1 hour') GROUP BY category ORDER BY c DESC LIMIT 8")
    services = db.query(
        "SELECT s.name, (SELECT status FROM service_health WHERE service_id=s.id ORDER BY id DESC LIMIT 1) status FROM services s")
    return {
        "confirmed": confirmed,
        "possible": possible,
        "active_offenses": active,
        "blocked": blocked,
        "events_total": events_total,
        "last_ingest_at": last_ingest["updated_at"] if last_ingest else None,
        "recent_activity": [dict(r) for r in recent],
        "service_health": [dict(r) for r in services],
        "empty": events_total == 0,
        "empty_hint": (
            "No events yet. Connect a Suricata sensor (POST EVE JSON to /api/soc/ingest/sensor "
            "with a sensor token), upload telemetry via /api/soc/ingest, or enable demo data."
            if events_total == 0 else None
        ),
    }


# ---------------- Offenses ----------------

@router.get("/offenses")
async def offenses(
    outcome: str | None = None, status: str | None = None, category: str | None = None,
    include_noise: bool = False, q: str | None = None,
    page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200), ctx=_require,
):
    where, params = [], []
    if outcome:
        where.append("outcome=?"); params.append(outcome)
    if status:
        where.append("status=?"); params.append(status)
    if category:
        where.append("category=?"); params.append(category)
    if q:
        where.append("(src_ip LIKE ? OR dest_ip LIKE ? OR category LIKE ?)"); params += [f"%{q}%"] * 3
    if not include_noise:
        # Default noise reduction: hide suppressed and routine blocked/attempted-low.
        where.append("status!='suppressed'")
        where.append("NOT (outcome IN ('blocked','attempted') AND severity='low')")
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    total = db.query_one(f"SELECT COUNT(*) c FROM offenses {clause}", params)["c"]
    rows = db.query(
        f"SELECT * FROM offenses {clause} "
        "ORDER BY CASE outcome WHEN 'confirmed' THEN 3 WHEN 'possible' THEN 2 "
        "WHEN 'attempted' THEN 1 ELSE 0 END DESC, last_seen DESC LIMIT ? OFFSET ?",
        params + [size, (page - 1) * size])
    return {"items": [_offense_row(r) for r in rows], "total": total, "page": page, "size": size}


def _offense_row(r) -> dict:
    d = dict(r)
    if d.get("evidence"):
        try:
            d["evidence"] = json.loads(d["evidence"])
        except Exception:
            pass
    return d


@router.get("/offenses/{oid}")
async def offense_detail(oid: int, ctx=_require, s: Settings = Depends(get_settings)):
    r = db.query_one("SELECT * FROM offenses WHERE id=?", (oid,))
    if not r:
        raise HTTPException(404, "Not found")
    d = _offense_row(r)
    top = db.query_one("SELECT * FROM events WHERE id=?", (r["top_event_id"],)) if r["top_event_id"] else None
    sample = db.query("SELECT id, ts, src_ip, http_method, http_url, http_status, outcome, signature FROM events WHERE offense_id=? ORDER BY id DESC LIMIT 25", (oid,))
    notes = db.query("SELECT * FROM offense_notes WHERE offense_id=? ORDER BY id", (oid,))
    d["top_event"] = _event_detail(dict(top), s) if top else None
    d["sample_events"] = [dict(x) for x in sample]
    d["notes"] = [dict(n) for n in notes]
    d["explanation"] = _explain(d)
    return d


def _explain(offense: dict) -> dict:
    cat = offense.get("category", "other")
    phrases = {
        "sql_injection": "An external host tried to manipulate a database query through application input.",
        "command_injection": "An external host attempted to run an operating-system command through an input parameter.",
        "path_traversal": "An external host tried to read files outside the intended directory.",
        "xss": "An external host tried to inject browser script into the application's output.",
        "ssti": "An external host tried to make the server evaluate template expressions.",
        "ssrf": "An external host tried to make the server send requests to internal addresses.",
        "lfi_rfi": "An external host tried to make the application include an arbitrary file.",
        "deserialization": "An external host sent serialized data that could trigger code execution.",
        "scanner": "An automated scanning tool probed the service.",
    }
    outcome_text = {
        "confirmed": "There is direct, attributable evidence the action succeeded. Investigate and patch urgently.",
        "possible": "The response suggests the attack may have worked, but proof is incomplete. Investigate.",
        "blocked": "Available evidence indicates a control stopped the attempt.",
        "attempted": "An attack pattern was seen, but there is not enough evidence to say whether it worked.",
    }
    return {
        "what_happened": phrases.get(cat, "An external host sent suspicious requests to the service."),
        "did_it_work": outcome_text.get(offense.get("outcome"), ""),
        "what_to_do": (
            "Open the strongest request below, review what was sent and how the service responded, "
            "then check the related Defense rule for a patch."
        ),
    }


class OffenseAction(BaseModel):
    action: str = Field(pattern="^(investigate|resolve|reopen|suppress|note|send_to_defense)$")
    reason: str | None = None
    note: str | None = None


@router.post("/offenses/{oid}/action")
async def offense_action(oid: int, body: OffenseAction, ctx=_require):
    r = db.query_one("SELECT * FROM offenses WHERE id=?", (oid,))
    if not r:
        raise HTTPException(404, "Not found")
    if body.action == "investigate":
        db.execute("UPDATE offenses SET status='investigating', updated_at=datetime('now') WHERE id=?", (oid,))
    elif body.action == "resolve":
        db.execute("UPDATE offenses SET status='resolved', updated_at=datetime('now') WHERE id=?", (oid,))
    elif body.action == "reopen":
        db.execute("UPDATE offenses SET status='new', updated_at=datetime('now') WHERE id=?", (oid,))
    elif body.action == "suppress":
        db.execute("UPDATE offenses SET status='suppressed', updated_at=datetime('now') WHERE id=?", (oid,))
        db.execute("INSERT INTO offense_notes(offense_id, body, label) VALUES (?,?,?)",
                   (oid, f"Suppressed: {body.reason or 'no reason given'}", ctx.label))
    elif body.action == "note":
        if not body.note:
            raise HTTPException(400, "note required")
        db.execute("INSERT INTO offense_notes(offense_id, body, label) VALUES (?,?,?)", (oid, body.note, ctx.label))
        db.execute("UPDATE offenses SET notes_count=notes_count+1 WHERE id=?", (oid,))
    elif body.action == "send_to_defense":
        fid = db.execute(
            "INSERT INTO findings(title, description, category, source, service_id, severity, status, refs, label) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (f"{r['category']} offense against {r['dest_ip']}",
             f"Correlated offense #{oid}: {r['event_count']} events, outcome={r['outcome']}.",
             r["category"], "soc", r["service_id"],
             {"critical": "critical", "high": "high"}.get(r["severity"], "medium"),
             "open", json.dumps({"offense_id": oid}), ctx.label),
        ).lastrowid
        auth.audit("offense.send_to_defense", f"offense={oid} finding={fid}", ctx)
        publish("findings.changed", {"id": fid, "op": "create"})
        return {"ok": True, "finding_id": fid}
    auth.audit(f"offense.{body.action}", str(oid), ctx)
    publish("offenses.changed", {"id": oid, "action": body.action})
    return {"ok": True}


# ---------------- Raw event explorer ----------------

@router.get("/events")
async def events(
    src_ip: str | None = None, dest_ip: str | None = None, dest_port: int | None = None,
    category: str | None = None, outcome: str | None = None, http_method: str | None = None,
    http_status: int | None = None, signature_id: int | None = None, q: str | None = None,
    since: str | None = None, until: str | None = None,
    page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200), ctx=_require,
):
    where, params = [], []
    def add(cond, val):
        where.append(cond); params.append(val)
    if src_ip: add("src_ip=?", src_ip)
    if dest_ip: add("dest_ip=?", dest_ip)
    if dest_port: add("dest_port=?", dest_port)
    if category: add("category=?", category)
    if outcome: add("outcome=?", outcome)
    if http_method: add("http_method=?", http_method)
    if http_status: add("http_status=?", http_status)
    if signature_id: add("signature_id=?", signature_id)
    if since: add("ts>=?", since)
    if until: add("ts<=?", until)
    if q:
        where.append("(http_url LIKE ? OR payload LIKE ? OR signature LIKE ?)"); params += [f"%{q}%"] * 3
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    total = db.query_one(f"SELECT COUNT(*) c FROM events {clause}", params)["c"]
    rows = db.query(
        f"SELECT id, ts, src_ip, dest_ip, dest_port, proto, category, outcome, http_method, "
        f"http_url, http_status, signature, offense_id FROM events {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [size, (page - 1) * size])
    return {"items": [dict(r) for r in rows], "total": total, "page": page, "size": size}


@router.get("/events/{eid}")
async def event_detail(eid: int, s: Settings = Depends(get_settings), ctx=_require):
    r = db.query_one("SELECT * FROM events WHERE id=?", (eid,))
    if not r:
        raise HTTPException(404, "Not found")
    return _event_detail(dict(r), s)


def _event_detail(ev: dict, s: Settings) -> dict:
    d = dict(ev)
    # per-event outcome + evidence (recomputed transparently from stored raw)
    rec = {}
    if d.get("raw"):
        try:
            rec = json.loads(d["raw"])
        except Exception:
            rec = {}
    d["outcome_detail"] = {"outcome": d.get("outcome"), "evidence": classify(d, rec)[1]}
    d["payload_inspector"] = _inspect_payload(d, s)
    return d


# ---------------- Payload inspector ----------------

def _highlight(text: str) -> list[dict]:
    hits = []
    for name, pat in TECHNIQUE_PATTERNS:
        for m in pat.finditer(text):
            hits.append({"technique": name, "match": m.group(0)[:80],
                         "start": m.start(), "end": m.end()})
    return hits[:20]


def _inspect_payload(ev: dict, s: Settings) -> dict:
    payload = ev.get("payload")
    b64 = ev.get("payload_b64")
    if not payload and not b64:
        return {"available": False, "message": "Payload unavailable — telemetry did not include request bytes."}
    truncated = False
    raw_text = payload or ""
    if b64 and not payload:
        try:
            raw_text = base64.b64decode(b64).decode("latin-1", "replace")
        except Exception:
            raw_text = ""
    if len(raw_text) > s.max_payload_display_bytes:
        raw_text = raw_text[: s.max_payload_display_bytes]
        truncated = True
    from urllib.parse import unquote_plus
    try:
        url_decoded = unquote_plus(raw_text)
    except Exception:
        url_decoded = raw_text
    hexview = raw_text.encode("latin-1", "replace")[:1024].hex(" ")
    return {
        "available": True,
        "raw": raw_text,                 # faithful original (escaped as text by the client)
        "url_decoded": url_decoded if url_decoded != raw_text else None,
        "hex": hexview,
        "base64_original_present": bool(b64),
        "suspicious": _highlight(url_decoded),
        "truncated": truncated,
        "note": "Original bytes are shown as escaped text and never executed.",
    }


# ---------------- Sensors ----------------

class SensorIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    kind: str = Field(default="suricata", max_length=30)


@router.get("/sensors")
async def list_sensors(ctx=_require):
    rows = db.query("SELECT id, name, kind, last_seen, enabled, created_at FROM sensors ORDER BY id")
    return {"items": [dict(r) for r in rows]}


@router.post("/sensors", status_code=201)
async def create_sensor(body: SensorIn, ctx=_require):
    tok = new_token()
    cur = db.execute("INSERT INTO sensors(name, token_hash, kind) VALUES (?,?,?)",
                     (body.name, token_hash(tok), body.kind))
    auth.audit("sensor.create", body.name, ctx)
    # token shown once; only its hash is stored
    return {"id": cur.lastrowid, "token": tok,
            "note": "Store this token now; it is shown only once and cannot be recovered."}


@router.delete("/sensors/{sid}")
async def delete_sensor(sid: int, ctx=_require):
    db.execute("DELETE FROM sensors WHERE id=?", (sid,))
    auth.audit("sensor.delete", str(sid), ctx)
    return {"ok": True}


@router.get("/ingest/health")
async def ingest_health(ctx=_require):
    last = db.query_one("SELECT value, updated_at FROM app_config WHERE key='soc_last_ingest'")
    sensors = db.query("SELECT name, last_seen, enabled FROM sensors")
    total = db.query_one("SELECT COUNT(*) c FROM events")["c"]
    return {
        "last_ingest": last["updated_at"] if last else None,
        "events_total": total,
        "sensors": [dict(s) for s in sensors],
    }
