"""Offense correlation engine.

Groups related events into coherent offenses so that, e.g., 10,000 automated
SQLi payloads against one service become ONE offense with counts and preserved
representative/strongest evidence — not 10,000 rows in the UI.

Grouping key: (category, dest_ip, dest_port, src_ip) within a sliding
correlation window. Different techniques from the same source are NOT merged.
If a later event carries stronger evidence, the offense's outcome is upgraded
and its strongest-evidence pointer is updated (never a redundant new offense).
"""
from __future__ import annotations

import json

from .. import db
from ..config import get_settings
from ..events_bus import publish
from .classify import OUTCOME_RANK, classify, merge_outcome

SEVERITY_FOR = {"confirmed": "critical", "possible": "high", "attempted": "medium", "blocked": "low"}


def _match_service(dest_ip, dest_port) -> int | None:
    row = db.query_one(
        "SELECT id FROM services WHERE host=? AND (port=? OR port IS NULL) LIMIT 1",
        (dest_ip, dest_port),
    )
    return row["id"] if row else None


def ingest_one(ev: dict, rec: dict | None, conn) -> dict:
    s = get_settings()
    outcome, evidence = classify(ev, rec)
    ev["outcome"] = outcome
    service_id = _match_service(ev.get("dest_ip"), ev.get("dest_port"))

    # Find an offense for this grouping key whose activity is within the
    # correlation window of THIS event's own timestamp (not wall-clock), so
    # replayed/historical telemetry (PCAP imports) groups correctly too.
    ev_ts = ev.get("ts")
    row = conn.execute(
        "SELECT id, outcome, event_count, top_event_id, status FROM offenses "
        "WHERE category=? AND dest_ip IS ? AND dest_port IS ? AND src_ip IS ? "
        "AND last_seen >= datetime(?, ?) AND first_seen <= datetime(?, ?) "
        "ORDER BY last_seen DESC LIMIT 1",
        (
            ev.get("category"), ev.get("dest_ip"), ev.get("dest_port"), ev.get("src_ip"),
            ev_ts, f"-{s.correlation_window_seconds} seconds",
            ev_ts, f"+{s.correlation_window_seconds} seconds",
        ),
    ).fetchone()

    is_new = row is None
    if is_new:
        cur = conn.execute(
            "INSERT INTO offenses(category, service_id, dest_ip, dest_port, src_ip, "
            "outcome, severity, first_seen, last_seen, event_count, distinct_payloads, "
            "evidence, status) VALUES (?,?,?,?,?,?,?,?,?,0,0,?, 'new')",
            (
                ev.get("category"), service_id, ev.get("dest_ip"), ev.get("dest_port"),
                ev.get("src_ip"), outcome, SEVERITY_FOR.get(outcome, "medium"),
                ev.get("ts"), ev.get("ts"), json.dumps(evidence),
            ),
        )
        offense_id = cur.lastrowid
        prev_outcome = outcome
    else:
        offense_id = row["id"]
        prev_outcome = row["outcome"]

    # Insert the event, linked to the offense.
    cur = conn.execute(
        "INSERT INTO events(ts, source, src_ip, src_port, dest_ip, dest_port, proto, "
        "service_id, flow_id, tx_id, event_type, category, signature, signature_id, "
        "severity, http_method, http_url, http_status, http_host, payload, payload_b64, "
        "raw, fingerprint, offense_id, outcome) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            ev.get("ts"), ev.get("source"), ev.get("src_ip"), ev.get("src_port"),
            ev.get("dest_ip"), ev.get("dest_port"), ev.get("proto"), service_id,
            ev.get("flow_id"), ev.get("tx_id"), ev.get("event_type"), ev.get("category"),
            ev.get("signature"), ev.get("signature_id"), ev.get("severity"),
            ev.get("http_method"), ev.get("http_url"), ev.get("http_status"),
            ev.get("http_host"), ev.get("payload"), ev.get("payload_b64"),
            (json.dumps(rec)[:8192] if rec else None), ev.get("fingerprint"),
            offense_id, outcome,
        ),
    )
    event_id = cur.lastrowid

    # Recompute aggregates for the offense (bounded queries, indexed).
    agg = conn.execute(
        "SELECT COUNT(*) c, COUNT(DISTINCT fingerprint) d, MIN(ts) f, MAX(ts) l "
        "FROM events WHERE offense_id=?",
        (offense_id,),
    ).fetchone()

    new_outcome = merge_outcome(prev_outcome, outcome)

    # Strongest-evidence pointer: keep event with the highest-ranked outcome.
    top_event_id = conn.execute(
        "SELECT id FROM events WHERE offense_id=? "
        "ORDER BY CASE outcome WHEN 'confirmed' THEN 3 WHEN 'possible' THEN 2 "
        "WHEN 'blocked' THEN 1 ELSE 0 END DESC, severity ASC, id DESC LIMIT 1",
        (offense_id,),
    ).fetchone()["id"]

    # Reopen a resolved/suppressed offense only if evidence genuinely upgraded.
    upgraded = OUTCOME_RANK.get(new_outcome, 0) > OUTCOME_RANK.get(prev_outcome, 0)
    status_clause = (
        ", status=CASE WHEN status IN ('resolved','suppressed') THEN 'new' ELSE status END"
        if upgraded else ""
    )

    conn.execute(
        "UPDATE offenses SET outcome=?, severity=?, event_count=?, distinct_payloads=?, "
        "first_seen=?, last_seen=?, top_event_id=?, evidence=?, updated_at=datetime('now')"
        + status_clause + " WHERE id=?",
        (
            new_outcome, SEVERITY_FOR.get(new_outcome, "medium"), agg["c"], agg["d"],
            agg["f"], agg["l"], top_event_id,
            _offense_evidence(conn, offense_id, new_outcome),
            offense_id,
        ),
    )

    return {
        "event_id": event_id,
        "offense_id": offense_id,
        "new_offense": is_new,
        "outcome": new_outcome,
        "upgraded": upgraded,
    }


def _offense_evidence(conn, offense_id: int, outcome: str) -> str:
    """Summarize offense evidence: the strongest event's classification, computed
    against its ORIGINAL record (parsed from the stored raw) so proof signals
    (response bodies, app_proof) are preserved — not lost to re-classification."""
    top = conn.execute(
        "SELECT * FROM events WHERE offense_id=? "
        "ORDER BY CASE outcome WHEN 'confirmed' THEN 3 WHEN 'possible' THEN 2 "
        "WHEN 'blocked' THEN 1 ELSE 0 END DESC, severity ASC, id DESC LIMIT 1",
        (offense_id,),
    ).fetchone()
    if not top:
        return json.dumps({"outcome": outcome, "signals": []})
    rec = {}
    if top["raw"]:
        try:
            rec = json.loads(top["raw"])
        except Exception:
            rec = {}
    ev_list = classify(dict(top), rec)[1]
    return json.dumps({"outcome": outcome, "signals": ev_list})


def ingest_batch(items: list[tuple[dict, dict | None]]) -> dict:
    """Process a batch under one transaction. Returns a summary."""
    conn = db.get_conn()
    results = {"ingested": 0, "new_offenses": 0, "upgrades": 0, "offense_ids": set()}
    conn.execute("BEGIN;")
    try:
        for ev, rec in items:
            r = ingest_one(ev, rec, conn)
            results["ingested"] += 1
            results["offense_ids"].add(r["offense_id"])
            if r["new_offense"]:
                results["new_offenses"] += 1
            if r["upgraded"]:
                results["upgrades"] += 1
        conn.execute("COMMIT;")
    except Exception:
        conn.execute("ROLLBACK;")
        raise
    results["offense_ids"] = sorted(results["offense_ids"])
    # notify live sessions (coalesced)
    publish("soc.ingest", {"ingested": results["ingested"], "new_offenses": results["new_offenses"], "upgrades": results["upgrades"]})
    return results
