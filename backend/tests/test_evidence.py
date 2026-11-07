"""Locks the evidence-based classification contract that the instrumented lab
(labs/demo_outcomes.py) demonstrates end-to-end:

  - With real application-level proof, an offense is CONFIRMED and its stored
    evidence cites the proof signal (application_proof), not a weaker one.
  - The SAME exploit payload WITHOUT that telemetry is not CONFIRMED.
"""
import json

from app import db
from app.soc import normalize
from app.soc.correlate import ingest_batch


def _eve(dst_port, url, payload, status, **extra):
    rec = {
        "timestamp": "2026-11-07T10:00:00", "event_type": "http",
        "src_ip": "10.9.9.9", "dest_ip": "127.0.0.1", "dest_port": dst_port,
        "proto": "TCP", "flow_id": 1,
        "http": {"url": url, "http_method": "GET", "status": status,
                 "http_request_body_printable": payload},
        "payload_printable": payload,
    }
    rec.update(extra)
    return rec


def _ingest(recs):
    items = [(normalize.from_eve(r), r) for r in recs]
    return ingest_batch([(e, r) for e, r in items if e])


def test_confirmed_from_flag_disclosure_cites_proof(client):
    for t in ("offense_notes", "offenses", "events"):
        db.execute(f"DELETE FROM {t}")
    # Full application visibility: response body carries the flag + attributable proof.
    _ingest([_eve(18080, "/item?id=0 UNION SELECT id,flag FROM secret",
                  "id=0 UNION SELECT id,flag FROM secret", 200,
                  response_body='{"rows":[[1,"iHACK{x}"]]}',
                  app_proof="flag disclosed to 10.9.9.9 on request #1")])
    o = db.query_one("SELECT outcome, evidence FROM offenses")
    assert o["outcome"] == "confirmed"
    signals = json.loads(o["evidence"])["signals"]
    assert signals and signals[0]["signal"] == "application_proof"


def test_same_exploit_without_telemetry_is_not_confirmed(client):
    for t in ("offense_notes", "offenses", "events"):
        db.execute(f"DELETE FROM {t}")
    # Passive/IDS-only: identical payload, but no response body / no proof.
    _ingest([_eve(18081, "/item?id=0 UNION SELECT id,flag FROM secret",
                  "id=0 UNION SELECT id,flag FROM secret", 200)])
    o = db.query_one("SELECT outcome FROM offenses")
    assert o["outcome"] != "confirmed"
    assert o["outcome"] in ("attempted", "possible")
