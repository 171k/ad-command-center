"""Bounded, allowlisted network probes shared by Attack/Services/Automation.

Safety model:
  - A destination may only be probed if it is registered in the `services`
    table (the scope allowlist). Active probing additionally requires the
    service to be marked authorized=1.
  - Every probe uses a short timeout. No Internet-wide or unbounded scanning.
  - These are connectivity/inspection helpers, not exploitation tools.
"""
from __future__ import annotations

import socket
import time

import httpx

from . import db
from .config import get_settings


class ScopeError(Exception):
    pass


def resolve_scope(host: str, port: int | None, require_authorized: bool) -> dict:
    """Confirm host[:port] is in the registry; return the service row or raise."""
    row = db.query_one(
        "SELECT * FROM services WHERE host=? AND (port=? OR ? IS NULL OR port IS NULL) LIMIT 1",
        (host, port, port),
    )
    if not row:
        raise ScopeError(f"{host}:{port or ''} is not in the authorized target registry.")
    if require_authorized and not row["authorized"]:
        raise ScopeError(f"{host} is registered but not marked authorized for active probing.")
    return dict(row)


def tcp_check(host: str, port: int, timeout: float | None = None) -> dict:
    s = get_settings()
    timeout = timeout or s.recon_timeout_seconds
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency = (time.perf_counter() - start) * 1000
            return {"status": "online", "latency_ms": round(latency, 1), "detail": "TCP connect ok"}
    except (OSError, socket.timeout) as e:
        return {"status": "offline", "latency_ms": None, "detail": f"{type(e).__name__}: {e}"}


def banner_grab(host: str, port: int, timeout: float | None = None) -> dict:
    s = get_settings()
    timeout = timeout or s.recon_timeout_seconds
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(256)
            except socket.timeout:
                data = b""
            return {"banner": data.decode("latin-1", "replace").strip() or None}
    except OSError as e:
        return {"banner": None, "error": f"{type(e).__name__}: {e}"}


# Lightweight technology fingerprint from observable headers only.
_TECH_HINTS = {
    "server": "Server header",
    "x-powered-by": "X-Powered-By",
    "x-aspnet-version": "ASP.NET",
    "x-generator": "Generator",
    "via": "Proxy/Via",
}


def http_inspect(url: str, method: str = "GET", timeout: float | None = None) -> dict:
    s = get_settings()
    timeout = timeout or s.recon_timeout_seconds
    start = time.perf_counter()
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as client:
            resp = client.request(method.upper(), url)
        latency = (time.perf_counter() - start) * 1000
        headers = {k.lower(): v for k, v in resp.headers.items()}
        tech = [label for h, label in _TECH_HINTS.items() if h in headers]
        body_preview = resp.text[:2000]
        return {
            "status_code": resp.status_code,
            "latency_ms": round(latency, 1),
            "headers": dict(resp.headers),
            "tech_fingerprint": [f"{label}: {headers[h]}" for h, label in _TECH_HINTS.items() if h in headers] or tech,
            "body_preview": body_preview,
            "content_type": headers.get("content-type"),
        }
    except httpx.HTTPError as e:
        return {"error": f"{type(e).__name__}: {e}", "status_code": None}


def record_health(service_id: int, result: dict) -> None:
    db.execute(
        "INSERT INTO service_health(service_id, status, latency_ms, detail) VALUES (?,?,?,?)",
        (service_id, result.get("status", "unknown"), result.get("latency_ms"), result.get("detail")),
    )


def check_service(row: dict) -> dict:
    proto = (row.get("protocol") or "tcp").lower()
    host, port = row["host"], row.get("port")
    if proto in ("http", "https") and port:
        url = f"{proto}://{host}:{port}/"
        r = http_inspect(url)
        if r.get("status_code") is not None:
            return {"status": "online", "latency_ms": r.get("latency_ms"),
                    "detail": f"HTTP {r['status_code']}"}
        return {"status": "offline", "latency_ms": None, "detail": r.get("error", "no response")}
    if port:
        return tcp_check(host, port)
    return {"status": "unknown", "latency_ms": None, "detail": "No port configured"}
