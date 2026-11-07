"""SOC correlation + classification tests, including the high-volume scenario."""
from app import db
from app.soc import normalize
from app.soc.classify import classify
from app.soc.correlate import ingest_batch


def _eve(src, url, payload, status=200, sig=None, ts="2026-11-07T10:00:00",
         dst="10.0.0.1", port=80, resp_body=None, proof=None):
    rec = {"timestamp": ts, "event_type": "http", "src_ip": src, "dest_ip": dst,
           "dest_port": port, "proto": "TCP", "flow_id": 1,
           "http": {"url": url, "http_method": "GET", "status": status,
                    "http_request_body_printable": payload},
           "payload_printable": payload}
    if sig:
        rec["alert"] = {"signature": sig, "signature_id": 1, "severity": 1}
    if resp_body is not None:
        rec["response_body"] = resp_body
    if proof is not None:
        rec["app_proof"] = proof
    return rec


def _ingest(recs):
    items = [(normalize.from_eve(r), r) for r in recs]
    return ingest_batch([(e, r) for e, r in items if e])


def _clean():
    for t in ("offense_notes", "offenses", "events"):
        db.execute(f"DELETE FROM {t}")


def test_high_volume_collapses_to_one_offense(client):
    _clean()
    recs = [_eve("1.2.3.4", f"/x?id=1' OR '1'='1&n={i}", "id=1' OR '1'='1",
                 ts=f"2026-11-07T10:00:{i % 60:02d}") for i in range(500)]
    summary = _ingest(recs)
    assert summary["ingested"] == 500
    offenses = db.query("SELECT * FROM offenses")
    assert len(offenses) == 1
    assert offenses[0]["event_count"] == 500
    # representative/strongest evidence pointer is preserved
    assert offenses[0]["top_event_id"] is not None


def test_confirmed_only_from_proof(client):
    _clean()
    # an IDS signature alone must NOT be confirmed
    _ingest([_eve("5.5.5.5", "/ping", "host=127.0.0.1; id", sig="ET Command Injection")])
    assert db.query_one("SELECT outcome FROM offenses")["outcome"] == "attempted"
    _clean()
    # explicit application proof -> confirmed
    _ingest([_eve("5.5.5.5", "/ping", "host=127.0.0.1; id",
                  proof="service logged shell exec of id")])
    assert db.query_one("SELECT outcome FROM offenses")["outcome"] == "confirmed"


def test_confirmed_from_command_output_in_response(client):
    _clean()
    _ingest([_eve("6.6.6.6", "/ping", "host=;id",
                  resp_body="uid=0(root) gid=0(root)")])
    assert db.query_one("SELECT outcome FROM offenses")["outcome"] == "confirmed"


def test_possible_from_sql_error(client):
    _clean()
    _ingest([_eve("7.7.7.7", "/x?id=1' OR '1'='1", "id=1' OR '1'='1", status=500,
                  resp_body="You have an error in your SQL syntax")])
    assert db.query_one("SELECT outcome FROM offenses")["outcome"] == "possible"


def test_blocked_classification(client):
    _clean()
    _ingest([_eve("8.8.8.8", "/x?id=1' OR '1'='1", "id=1' OR '1'='1", status=403)])
    assert db.query_one("SELECT outcome FROM offenses")["outcome"] == "blocked"


def test_200_alone_is_not_success(client):
    _clean()
    # attack payload, HTTP 200, but no corroborating response evidence
    _ingest([_eve("9.9.9.9", "/x?id=1' OR '1'='1", "id=1' OR '1'='1", status=200)])
    assert db.query_one("SELECT outcome FROM offenses")["outcome"] == "attempted"


def test_offense_upgrade_preserves_group(client):
    _clean()
    recs = [_eve("1.1.1.1", "/x?id=1' OR '1'='1", "id=1' OR '1'='1",
                 ts=f"2026-11-07T10:00:{i:02d}") for i in range(20)]
    # last one leaks a SQL error -> upgrade to possible, same offense
    recs.append(_eve("1.1.1.1", "/x?id=1' OR '1'='1", "id=1' OR '1'='1", status=500,
                     resp_body="SQL syntax error", ts="2026-11-07T10:01:00"))
    summary = _ingest(recs)
    assert summary["upgrades"] >= 1
    rows = db.query("SELECT * FROM offenses")
    assert len(rows) == 1
    assert rows[0]["outcome"] == "possible"
    assert rows[0]["event_count"] == 21


def test_different_techniques_not_merged(client):
    _clean()
    _ingest([
        _eve("2.2.2.2", "/x?id=1' OR '1'='1", "id=1' OR '1'='1"),
        _eve("2.2.2.2", "/ping", "host=;id", sig="cmd"),
    ])
    cats = {r["category"] for r in db.query("SELECT category FROM offenses")}
    assert "sql_injection" in cats and "command_injection" in cats
    assert len(cats) == 2


def test_payload_inspector_unavailable(client):
    _clean()
    # flow event without payload
    rec = {"timestamp": "2026-11-07T10:00:00", "event_type": "flow",
           "src_ip": "3.3.3.3", "dest_ip": "10.0.0.1", "dest_port": 80, "proto": "TCP"}
    _ingest([rec])
    ev = db.query_one("SELECT id FROM events LIMIT 1")
    assert ev is not None


def test_classify_evidence_is_transparent():
    ev = normalize.from_eve(_eve("4.4.4.4", "/ping", "host=;id",
                                 resp_body="uid=0(root)"))
    outcome, evidence = classify(ev, {"response_body": "uid=0(root)"})
    assert outcome == "confirmed"
    assert evidence and "signal" in evidence[0]
