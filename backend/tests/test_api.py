"""API-level workflow tests across workspaces."""


def test_findings_crud_and_notes(auth):
    client, h = auth
    r = client.post("/api/findings", json={"title": "SQLi in /item", "severity": "high",
                                           "category": "defense"}, headers=h)
    fid = r.json()["id"]
    assert client.get(f"/api/findings/{fid}").json()["title"] == "SQLi in /item"
    client.put(f"/api/findings/{fid}", json={"title": "SQLi in /item", "severity": "high",
                                             "status": "resolved"}, headers=h)
    assert client.get(f"/api/findings/{fid}").json()["status"] == "resolved"
    client.post(f"/api/findings/{fid}/notes", json={"body": "patched with prepared stmt"}, headers=h)
    assert len(client.get(f"/api/findings/{fid}").json()["notes"]) == 1
    # search filter
    assert client.get("/api/findings", params={"q": "SQLi"}).json()["total"] == 1


def test_services_scope_enforced(auth):
    client, h = auth
    # out-of-scope recon rejected
    assert client.post("/api/attack/recon/tcp", json={"host": "203.0.113.9", "port": 80},
                       headers=h).status_code == 403
    # register as authorized, now allowed to probe (will just fail to connect, not 403)
    client.post("/api/services", json={"name": "opp", "host": "203.0.113.9", "port": 80,
                                       "protocol": "tcp", "owner": "opponent", "authorized": True}, headers=h)
    r = client.post("/api/attack/recon/tcp", json={"host": "203.0.113.9", "port": 80}, headers=h)
    assert r.status_code == 200
    assert r.json()["status"] in ("online", "offline")


def test_scripts_revisions(auth):
    client, h = auth
    sid = client.post("/api/automation/scripts", json={"name": "s", "language": "python",
                                                        "body": "print(1)"}, headers=h).json()["id"]
    client.put(f"/api/automation/scripts/{sid}", json={"name": "s", "language": "python",
                                                       "body": "print(2)"}, headers=h)
    detail = client.get(f"/api/automation/scripts/{sid}").json()
    assert detail["body"] == "print(2)"
    assert len(detail["revisions"]) == 1  # snapshot of print(1)


def test_utils_operations(auth):
    client, h = auth
    assert client.post("/api/automation/utils", json={"op": "b64_decode", "text": "aGVsbG8="},
                       headers=h).json()["result"] == "hello"
    jwt = client.post("/api/automation/utils", json={"op": "jwt_decode",
        "text": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig"}, headers=h).json()
    assert jwt["result"]["signature_verified"] is False  # honest: not verified


def test_soc_ingest_api_and_offense_detail(auth):
    client, h = auth
    events = [{"timestamp": "2026-11-07T10:00:00", "event_type": "http",
               "src_ip": "1.2.3.4", "dest_ip": "10.0.0.1", "dest_port": 80, "proto": "TCP",
               "http": {"url": "/ping", "http_method": "POST", "status": 200,
                        "http_request_body_printable": "host=;id"},
               "payload_printable": "host=;id", "app_proof": "shell exec recorded"}]
    r = client.post("/api/soc/ingest", json={"events": events}, headers=h)
    assert r.json()["ingested"] == 1
    offs = client.get("/api/soc/offenses").json()["items"]
    assert len(offs) == 1
    oid = offs[0]["id"]
    detail = client.get(f"/api/soc/offenses/{oid}").json()
    assert detail["outcome"] == "confirmed"
    assert "what_happened" in detail["explanation"]
    # payload inspector present on strongest event
    assert detail["top_event"]["payload_inspector"]["available"] is True


def test_dashboard_empty_state(auth):
    client, h = auth
    d = client.get("/api/soc/dashboard").json()
    assert d["empty"] is True
    assert "Connect a Suricata sensor" in d["empty_hint"]


def test_flag_dedup(auth):
    client, h = auth
    r1 = client.post("/api/attack/flags", json={"value": "FLAG{abc}"}, headers=h)
    r2 = client.post("/api/attack/flags", json={"value": "FLAG{abc}"}, headers=h)
    assert r1.json()["duplicate"] is False
    assert r2.json()["duplicate"] is True


def test_send_offense_to_defense(auth):
    client, h = auth
    events = [{"timestamp": "2026-11-07T10:00:00", "event_type": "http", "src_ip": "9.9.9.9",
               "dest_ip": "10.0.0.1", "dest_port": 80, "proto": "TCP",
               "http": {"url": "/x?id=1' OR '1'='1", "http_method": "GET", "status": 200},
               "payload_printable": "id=1' OR '1'='1"}]
    client.post("/api/soc/ingest", json={"events": events}, headers=h)
    oid = client.get("/api/soc/offenses").json()["items"][0]["id"]
    r = client.post(f"/api/soc/offenses/{oid}/action", json={"action": "send_to_defense"}, headers=h)
    assert r.json()["finding_id"]
    assert client.get("/api/findings").json()["total"] == 1
