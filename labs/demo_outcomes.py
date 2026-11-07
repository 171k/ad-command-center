"""End-to-end proof for: "how do we confirm an attack actually succeeded?"

Pipeline (all real, no synthetic SIEM events):
  1. Start the instrumented vulnerable service (labs/vuln_service.py).
  2. Launch REAL HTTP SQL-injection attacks against it over the network.
  3. The service emits its own application-level telemetry (EVE JSON), including
     response bodies and an `app_proof` marker when the real flag is disclosed.
  4. Forward that telemetry to the Command Center's sensor ingest endpoint.
  5. Read back the SIEM's verdicts via its API and print them with evidence.
  6. Contrast: replay the SAME winning exploit with only passive/IDS-level data
     (no response body, no proof) -> the SIEM honestly refuses to say CONFIRMED.

Env: BASE, SENSOR_TOKEN, CC_PASSWORD.
"""
from __future__ import annotations

import json
import os
import sys
import time
from urllib.parse import unquote

import httpx

import vuln_service

BASE = os.environ["BASE"].rstrip("/")
TOKEN = os.environ["SENSOR_TOKEN"]
PASSWORD = os.environ["CC_PASSWORD"]
VULN_PORT = 18080
PASSIVE_PORT = 18081

ATTACKS = [
    ("EXFILTRATION (works)", "/item?id=0 UNION SELECT id, flag FROM secret-- "),
    ("ERROR-BASED (DB error)", "/item?id=1 UNION SELECT flag FROM secret"),
    ("BLIND/BENIGN INJECTION", "/item?id=1 OR 1=1"),
]


def run_attacks():
    print("\n[2] Launching real HTTP attacks against the vulnerable service...")
    with httpx.Client(base_url=f"http://127.0.0.1:{VULN_PORT}", timeout=5, trust_env=False) as cli:
        for name, path in ATTACKS:
            r = cli.get(path)
            leaked = vuln_service.FLAG in r.text
            print(f"    - {name:<24} HTTP {r.status_code}  flag_in_response={leaked}")


def forward(events, label):
    ndjson = "\n".join(json.dumps(e) for e in events)
    with httpx.Client(timeout=15, trust_env=False) as c:
        r = c.post(f"{BASE}/api/soc/ingest/sensor", content=ndjson,
                   headers={"Authorization": f"Bearer {TOKEN}",
                            "Content-Type": "application/x-ndjson"})
    r.raise_for_status()
    print(f"    forwarded {len(events)} {label} record(s) -> {r.json()}")
    return r.json()


def login() -> httpx.Client:
    cli = httpx.Client(base_url=BASE, timeout=10, trust_env=False)
    r = cli.post("/api/auth/login", json={"password": PASSWORD, "label": "Demo"})
    r.raise_for_status()
    return cli


def show_offenses(cli: httpx.Client):
    offs = cli.get("/api/soc/offenses?include_noise=true").json()["items"]
    print("\n[5] SIEM verdicts (read back from the API):")
    print(f"    {'OUTCOME':<11} {'TECHNIQUE':<16} {'TARGET':<16} EVENTS  TOP-EVIDENCE")
    for o in offs:
        detail = cli.get(f"/api/soc/offenses/{o['id']}").json()
        sig = (detail.get("evidence") or {}).get("signals", [])
        top = sig[0]["signal"] if sig else "-"
        tgt = f"{o['dest_ip']}:{o['dest_port']}"
        print(f"    {o['outcome'].upper():<11} {o['category']:<16} {tgt:<16} "
              f"{o['event_count']:>5}   {top}")
    return offs


def main():
    print("[1] Starting instrumented vulnerable service on :%d (flag loaded in its DB)" % VULN_PORT)
    vuln_service.start(VULN_PORT)
    time.sleep(0.4)

    run_attacks()

    events = vuln_service.drain_events()
    print(f"\n[3] Service emitted {len(events)} application-level telemetry records.")
    # keep only the attack requests (drop the service's own '/' probes if any)
    attack_events = [e for e in events if "/item" in e["http"]["url"]]

    print("\n[4] Forwarding FULL application telemetry (with response bodies + proof):")
    forward(attack_events, "full-visibility")

    print("\n[4b] Forwarding the SAME winning exploit as PASSIVE/IDS-only data")
    print("     (no response body, no app_proof) against a different port 8081:")
    exfil = next(e for e in attack_events if "UNION SELECT id, flag" in unquote(e["http"]["url"]))
    passive = json.loads(json.dumps(exfil))
    passive.pop("response_body", None)
    passive.pop("app_proof", None)
    passive["dest_port"] = PASSIVE_PORT
    passive["http"]["status"] = 200
    passive["alert"] = {"signature": "ET WEB SQL Injection Attempt", "signature_id": 2001, "severity": 1}
    forward([passive], "passive-only")

    cli = login()
    offs = show_offenses(cli)

    # Assertions that back the write-up.
    by_target = {f"{o['dest_ip']}:{o['dest_port']}": o for o in offs}
    full = by_target.get(f"127.0.0.1:{VULN_PORT}")
    passive_o = by_target.get(f"127.0.0.1:{PASSIVE_PORT}")
    print("\n[6] Conclusion:")
    if full and full["outcome"] == "confirmed":
        print("    FULL application visibility  -> CONFIRMED (real flag disclosure proof).")
    else:
        print("    FULL visibility outcome:", full and full["outcome"])
    if passive_o and passive_o["outcome"] in ("attempted", "possible"):
        print(f"    PASSIVE/IDS-only visibility   -> {passive_o['outcome'].upper()} "
              "(same exploit, but no proof -> SIEM does NOT claim success).")
    ok = full and full["outcome"] == "confirmed" and passive_o and passive_o["outcome"] != "confirmed"
    print("\nRESULT:", "PASS — evidence-based classification verified." if ok else "CHECK OUTPUT")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
