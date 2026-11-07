"""Curated script library + synthetic attack-traffic generator.

The scripts below are real, runnable references (not placeholder prints). The
traffic generator produces Suricata-EVE-shaped records used by the test suite
and the optional demo mode to exercise correlation and classification.
"""
from __future__ import annotations

import json
import random

from . import db

CURATED_SCRIPTS = [
    {
        "name": "TCP port sweep (bounded)",
        "language": "python",
        "category": "reconnaissance",
        "kind": "script",
        "notes": "Checks a small, explicit port list against ONE authorized host with timeouts.",
        "body": '''#!/usr/bin/env python3
"""Bounded TCP connectivity check. Authorized targets only."""
import socket, sys

def check(host, ports, timeout=2.0):
    for p in ports:
        try:
            with socket.create_connection((host, p), timeout=timeout):
                print(f"{host}:{p} open")
        except OSError:
            print(f"{host}:{p} closed")

if __name__ == "__main__":
    host = sys.argv[1]
    ports = [int(x) for x in sys.argv[2:]] or [80, 443, 22]
    check(host, ports)
''',
    },
    {
        "name": "HTTP header + title grab",
        "language": "python",
        "category": "reconnaissance",
        "kind": "script",
        "notes": "Fetches headers and <title> for fingerprinting. Authorized targets only.",
        "body": '''#!/usr/bin/env python3
import sys, re, httpx
url = sys.argv[1]
r = httpx.get(url, timeout=5, verify=False)
print("Status:", r.status_code)
for k, v in r.headers.items():
    print(f"{k}: {v}")
m = re.search(r"<title>(.*?)</title>", r.text, re.I | re.S)
print("Title:", m.group(1).strip() if m else "(none)")
''',
    },
    {
        "name": "Flag submitter (adapter template)",
        "language": "python",
        "category": "flag_submission",
        "kind": "script",
        "notes": "Template for the organizer's documented API. Fill in URL/field/auth per the rules.",
        "body": '''#!/usr/bin/env python3
"""Submit flags to the organizer API. Configure per competition rules."""
import os, sys, httpx

SUBMIT_URL = os.environ["SUBMIT_URL"]      # e.g. http://scoreboard/flags
FIELD = os.environ.get("FLAG_FIELD", "flag")
TOKEN = os.environ.get("TEAM_TOKEN", "")

def submit(flag):
    headers = {"X-Team-Token": TOKEN} if TOKEN else {}
    r = httpx.post(SUBMIT_URL, json={FIELD: flag}, headers=headers, timeout=5)
    return r.status_code, r.text

if __name__ == "__main__":
    for flag in sys.stdin.read().split():
        code, body = submit(flag)
        print(flag, code, body[:80])
''',
    },
    {
        "name": "Suricata EVE tail -> Command Center",
        "language": "bash",
        "category": "log_processing",
        "kind": "script",
        "notes": "Streams eve.json lines to the sensor ingest endpoint. Set SENSOR_TOKEN and URL.",
        "body": '''#!/usr/bin/env bash
# Forward new Suricata EVE records to the Command Center sensor endpoint.
set -euo pipefail
EVE="${EVE:-/var/log/suricata/eve.json}"
URL="${URL:-https://localhost/api/soc/ingest/sensor}"
TOKEN="${SENSOR_TOKEN:?set SENSOR_TOKEN}"

tail -n0 -F "$EVE" | while IFS= read -r line; do
  curl -sS -H "Authorization: Bearer $TOKEN" \\
       -H "Content-Type: application/x-ndjson" \\
       --data-binary "$line" "$URL" >/dev/null || true
done
''',
    },
    {
        "name": "Patch regression harness",
        "language": "python",
        "category": "patch_testing",
        "kind": "script",
        "notes": "Runs a payload against a before/after endpoint and asserts the fix holds.",
        "body": '''#!/usr/bin/env python3
import sys, httpx
BASE = sys.argv[1]
PAYLOAD = sys.argv[2] if len(sys.argv) > 2 else "' OR '1'='1"
r = httpx.get(f"{BASE}/item", params={"id": PAYLOAD}, timeout=5)
assert r.status_code in (400, 404), f"regression: unexpected {r.status_code}"
print("OK: injection rejected")
''',
    },
    {
        "name": "SQLi probe (authorized lab)",
        "language": "python",
        "category": "exploitation_templates",
        "kind": "exploit_template",
        "notes": "Verification template — authorized lab targets only. Distinguishes behaviour, not a universal exploit.",
        "body": '''#!/usr/bin/env python3
"""Boolean-based SQLi verification against an AUTHORIZED lab endpoint."""
import sys, httpx
base = sys.argv[1]
true_p = httpx.get(f"{base}", params={"id": "1 OR 1=1"}, timeout=5, verify=False)
false_p = httpx.get(f"{base}", params={"id": "1 AND 1=2"}, timeout=5, verify=False)
print("len(true)=", len(true_p.text), "len(false)=", len(false_p.text))
print("Likely injectable" if len(true_p.text) != len(false_p.text) else "Inconclusive")
''',
    },
]


def seed_library(force: bool = False) -> int:
    existing = db.query_one("SELECT COUNT(*) c FROM scripts")["c"]
    if existing and not force:
        return 0
    n = 0
    for s in CURATED_SCRIPTS:
        db.execute(
            "INSERT INTO scripts(name, language, category, body, notes, tags, kind, label) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (s["name"], s["language"], s["category"], s["body"], s["notes"],
             json.dumps([s["category"]]), s["kind"], "seed"),
        )
        n += 1
    return n


# ------------- synthetic attack traffic (EVE-shaped) -------------

_SQLI = ["id=1' OR '1'='1", "id=1 UNION SELECT username,password FROM users",
         "id=1'; DROP TABLE x-- ", "id=1' AND SLEEP(5)-- "]
_CMDI = ["host=127.0.0.1; id", "host=127.0.0.1 && whoami", "host=`cat /etc/passwd`"]
_TRAV = ["file=../../../../etc/passwd", "file=..%2f..%2f..%2fetc%2fpasswd"]


def _eve(src, dst, port, method, url, status, payload, sig=None, ts="2026-11-07T10:00:00",
         flow=None, resp_body=None, proof=None):
    rec = {
        "timestamp": ts, "event_type": "http", "src_ip": src, "src_port": 44444,
        "dest_ip": dst, "dest_port": port, "proto": "TCP", "flow_id": flow or random.randint(1, 1_000_000),
        "http": {"hostname": dst, "url": url, "http_method": method, "status": status,
                 "http_request_body_printable": payload},
        "payload_printable": payload,
    }
    if sig:
        rec["alert"] = {"signature": sig, "signature_id": 2001, "severity": 1}
    if resp_body is not None:
        rec["response_body"] = resp_body
    if proof is not None:
        rec["app_proof"] = proof
    return rec


def demo_events(target_ip: str = "10.10.0.5", target_port: int = 8080) -> list[dict]:
    """A realistic mix: a noisy failed SQLi burst, a blocked set, one POSSIBLE,
    one CONFIRMED (with explicit app proof), plus traversal + scanner noise."""
    evs: list[dict] = []
    atk = "10.13.37.9"
    # 1) high-volume failed SQLi burst from one attacker -> should collapse to ONE offense
    for i in range(60):
        evs.append(_eve(atk, target_ip, target_port, "GET",
                        f"/item?{random.choice(_SQLI)}", 200,
                        random.choice(_SQLI), sig="ET WEB SQL Injection Attempt",
                        ts=f"2026-11-07T10:{i // 60:02d}:{i % 60:02d}"))
    # 2) one POSSIBLE within the SAME burst: a SQL error leaks in the response.
    #    This must UPGRADE the existing SQLi offense (not spawn a new one), and
    #    remain discoverable even though thousands of prior attempts failed.
    evs.append(_eve(atk, target_ip, target_port, "GET", "/item?id=1' OR '1'='1", 500,
                    "id=1' OR '1'='1", sig="ET WEB SQL Injection Attempt",
                    resp_body="You have an error in your SQL syntax near \"'1'='1\"",
                    ts="2026-11-07T10:05:00"))
    # 3) blocked command injection from a different attacker
    for i in range(10):
        evs.append(_eve("10.20.0.2", target_ip, target_port, "POST", "/ping", 403,
                        random.choice(_CMDI), sig="ET WEB Command Injection",
                        ts=f"2026-11-07T10:06:{i:02d}"))
    # 4) CONFIRMED command injection with explicit instrumented proof
    evs.append(_eve("10.20.0.7", target_ip, target_port, "POST", "/ping", 200,
                    "host=127.0.0.1; id", sig="ET WEB Command Injection",
                    resp_body="uid=0(root) gid=0(root) groups=0(root)",
                    proof="service recorded shell exec of 'id' for request tx=991",
                    ts="2026-11-07T10:07:00"))
    # 5) path traversal attempts (attempted/unknown)
    for p in _TRAV:
        evs.append(_eve("10.30.0.4", target_ip, target_port, "GET", f"/dl?{p}", 404, p,
                        ts="2026-11-07T10:08:00"))
    # 6) scanner noise
    evs.append(_eve("10.40.0.1", target_ip, target_port, "GET", "/", 200,
                    "User-Agent: sqlmap/1.7", sig="ET SCAN sqlmap", ts="2026-11-07T10:09:00"))
    return evs
