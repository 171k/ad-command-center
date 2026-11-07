"""An intentionally vulnerable, INSTRUMENTED test service.

Purpose: prove the SIEM classifies CONFIRMED only from real application-level
evidence. This is a genuine (deliberately insecure) web app with a real SQL
injection, a real secret flag in its database, and instrumentation that emits
Suricata-EVE-shaped telemetry for every request.

The instrumentation is the key idea: the service KNOWS its own flag, so when a
response actually contains the flag it emits `app_proof` — direct, attributable
evidence that the flag was disclosed to a specific client on a specific request.
That is exactly the evidence the SIEM's CONFIRMED path requires.

Dependency-free (stdlib only). Do NOT expose this to any untrusted network.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

FLAG = "iHACK{instrumented_proof_not_a_guess}"
BOUND_PORT = 8080
_counter = {"n": 0}
_events: list[dict] = []           # collected EVE records (the service's own telemetry)
_lock = threading.Lock()


def _build_db() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.executescript(
        """
        CREATE TABLE items(id INTEGER, name TEXT);
        INSERT INTO items VALUES (1,'widget'),(2,'gadget'),(3,'sprocket');
        CREATE TABLE secret(id INTEGER, flag TEXT);
        INSERT INTO secret VALUES (1, ?);
        """.replace("?", f"'{FLAG}'")
    )
    return db


class Handler(BaseHTTPRequestHandler):
    db: sqlite3.Connection = None  # set on the server instance

    def log_message(self, *a):  # silence default stderr logging
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        client = self.client_address[0]
        status, body = 200, ""

        if parsed.path == "/item":
            raw_id = qs.get("id", ["1"])[0]
            # VULNERABLE: user input concatenated straight into SQL (CWE-89).
            query = f"SELECT id, name FROM items WHERE id = {raw_id}"
            try:
                rows = self.server.db.execute(query).fetchall()
                body = json.dumps({"query_ok": True, "rows": rows})
                status = 200
            except sqlite3.Error as e:
                # Real DB error surfaces to the client (information leak).
                body = json.dumps({"error": f"SQL error: {e}"})
                status = 500
        elif parsed.path == "/":
            body = json.dumps({"service": "demo-shop", "endpoints": ["/item?id="]})
        else:
            status, body = 404, json.dumps({"error": "not found"})

        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Server", "demo-shop/1.0")
        self.end_headers()
        self.wfile.write(data)

        _emit(self.command, self.path, status, body, client, self.headers.get("Host", "demo-shop"))


def _emit(method, path, status, body, client, host):
    """Instrumented telemetry: emit an EVE-shaped record; attach app_proof when
    the real flag was disclosed in the response (attributable success evidence)."""
    with _lock:
        _counter["n"] += 1
        n = _counter["n"]
    payload = urlparse(path).query
    rec = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
        "event_type": "http",
        "src_ip": client,
        "src_port": 40000 + (n % 2000),
        "dest_ip": "127.0.0.1",
        "dest_port": BOUND_PORT,
        "proto": "TCP",
        "flow_id": 900000 + n,
        "http": {
            "hostname": host, "url": path, "http_method": method,
            "status": status, "http_request_body_printable": payload,
        },
        "payload_printable": payload,
        "response_body": body[:2000],          # app-level visibility (our own server)
    }
    if FLAG in body:
        rec["app_proof"] = (
            f"secret flag disclosed in response body to {client} on request #{n} "
            f"(tx flow_id={rec['flow_id']})"
        )
    with _lock:
        _events.append(rec)


def start(port: int = 8080) -> ThreadingHTTPServer:
    global BOUND_PORT
    BOUND_PORT = port
    ThreadingHTTPServer.allow_reuse_address = False  # fail loudly if the port is taken
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.db = _build_db()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def drain_events() -> list[dict]:
    with _lock:
        out = list(_events)
        _events.clear()
    return out
