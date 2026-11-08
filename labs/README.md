# Labs: instrumented proof of outcome classification

This directory answers the question *"how do we confirm an attack actually
succeeded?"* with a **real, runnable demonstration**, not synthetic SIEM events.

## What's here

- **`vuln_service.py`**: a deliberately vulnerable, **instrumented** web service.
  It has a real SQL-injection flaw, a real secret flag in its database and emits
  Suricata-EVE-shaped telemetry for every request. Because it knows its own flag,
  it attaches an `app_proof` marker when a response actually discloses the flag: direct, attributable evidence tied to a specific request.
- **`demo_outcomes.py`**: launches the service, performs **real HTTP SQLi attacks**
  over the network, forwards the service's telemetry to the Command Center and
  reads back the SIEM's verdicts.

> ⚠️ `vuln_service.py` is intentionally insecure. Run it only on localhost.

## What it proves

Running it produces (verified):

```
[2] Launching real HTTP attacks against the vulnerable service...
    - EXFILTRATION (works)     HTTP 200  flag_in_response=True
    - ERROR-BASED (DB error)   HTTP 500  flag_in_response=False
    - BLIND/BENIGN INJECTION   HTTP 200  flag_in_response=False

[5] SIEM verdicts (read back from the API):
    OUTCOME     TECHNIQUE        TARGET           EVENTS  TOP-EVIDENCE
    CONFIRMED   sql_injection    127.0.0.1:18080      3   application_proof
    ATTEMPTED   sql_injection    127.0.0.1:18081      1   attack_pattern
```

Two points for the record:

1. **CONFIRMED comes from real application evidence**, the flag was actually
   returned to the attacker and the service recorded it. Not an IDS guess, not an
   HTTP-200 assumption.
2. **The same winning exploit, replayed with only passive/IDS-level data** (no
   response body, no proof), is classified **ATTEMPTED**, the SIEM refuses to
   claim success it cannot prove. This is the honesty guarantee in action.

The same contract is locked by `backend/tests/test_evidence.py`.

## Run it

```bash
cd backend
# fresh demo DB + sensor token
export ADCC_DB_PATH="$PWD/../data/demo.db" ADCC_SECRET_KEY=demo
python -m app.admin set-password --password demopass12345
TOKEN=$(python -m app.admin create-sensor demo | tail -1 | tr -d ' ')
python -m uvicorn app.main:app --port 8010 &          # start the Command Center
cd ../labs
BASE=http://127.0.0.1:8010 SENSOR_TOKEN=$TOKEN CC_PASSWORD=demopass12345 \
  python demo_outcomes.py
```

## Why this matters for the real competition

The CONFIRMED verdict depends on the SIEM having **application-level telemetry**
(response bodies / instrumentation) from the defended service. In an A&D CTF you
typically run your own vulnerable service, so you *can* capture that, ship its
access logs (with responses) or run the instrumentation pattern shown here. Where
you only have passive network data, outcomes stay POSSIBLE/ATTEMPTED by design.
See `docs/NETWORK.md` and `docs/SIEM.md`.
