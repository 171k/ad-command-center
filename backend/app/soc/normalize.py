"""Normalize heterogeneous telemetry into one internal event schema.

Supported inputs:
  - Suricata EVE JSON records (alert / http / flow / fileinfo)
  - Generic structured HTTP access-log rows (dict)
  - Synthetic test events (same shape as EVE http)

Also derives:
  - a normalized attack *category* (technique) from signatures + payload text
  - a *fingerprint* that collapses near-identical automated payloads so bursts
    group into one offense instead of thousands.

Nothing here executes payloads; payload bytes are stored as escaped text only.
"""
from __future__ import annotations

import base64
import re
from datetime import datetime, timezone
from urllib.parse import unquote_plus

# Technique signatures matched against URL + decoded payload (deterministic).
TECHNIQUE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("sql_injection", re.compile(r"(\bunion\b.+\bselect\b|'\s*or\s*'?1'?\s*=\s*'?1|sleep\s*\(|benchmark\s*\(|information_schema|--\s|\bor\b\s+1\s*=\s*1)", re.I)),
    ("command_injection", re.compile(r"(;\s*(id|whoami|cat|uname|ls)\b|\|\s*(id|whoami|nc|bash|sh)\b|\$\(.*\)|`.*`|&&\s*\w+)", re.I)),
    ("path_traversal", re.compile(r"(\.\./|\.\.%2f|%2e%2e%2f|/etc/passwd|\.\.\\|boot\.ini)", re.I)),
    ("ssti", re.compile(r"(\{\{.*\}\}|\$\{.*\}|<%=.*%>|#\{.*\})", re.I)),
    ("xss", re.compile(r"(<script\b|onerror\s*=|onload\s*=|javascript:|<img[^>]+src\s*=\s*x|alert\s*\()", re.I)),
    ("ssrf", re.compile(r"(169\.254\.169\.254|metadata\.google|127\.0\.0\.1|localhost|file://|gopher://|dict://)", re.I)),
    ("lfi_rfi", re.compile(r"(php://filter|php://input|data://|expect://|=https?://)", re.I)),
    ("deserialization", re.compile(r"(rO0AB|aced0005|__reduce__|O:\d+:\")", re.I)),
    ("scanner", re.compile(r"(nikto|sqlmap|nmap|masscan|acunetix|dirbuster|gobuster|wpscan|nuclei)", re.I)),
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def canonical_ts(value: str | None) -> str:
    """Normalize any timestamp to SQLite's 'YYYY-MM-DD HH:MM:SS' (UTC, naive).

    Suricata emits ISO8601 with a 'T' and a timezone; we must match SQLite's
    datetime() output so lexicographic comparisons in the correlation window
    are correct.
    """
    if not value:
        return _now_iso()
    try:
        s = str(value).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return str(value)[:19].replace("T", " ")


def _decode_payload(text: str | None) -> str | None:
    if not text:
        return None
    try:
        return unquote_plus(text)
    except Exception:
        return text


def classify_technique(url: str | None, payload: str | None, signature: str | None) -> str:
    haystack = " ".join(filter(None, [url, payload, signature]))
    decoded = _decode_payload(haystack) or ""
    combined = f"{haystack}\n{decoded}"
    for name, pat in TECHNIQUE_PATTERNS:
        if pat.search(combined):
            return name
    if signature:
        return "ids_alert"
    return "other"


def fingerprint(category: str, url: str | None, payload: str | None) -> str:
    """Collapse variable parts so automated payloads of one kind map together."""
    raw = _decode_payload(" ".join(filter(None, [url, payload]))) or ""
    raw = raw.lower()
    raw = re.sub(r"\d+", "N", raw)                 # numbers -> N
    raw = re.sub(r"['\"]", "", raw)                # strip quotes
    raw = re.sub(r"[a-f0-9]{16,}", "HEX", raw)     # long hex blobs
    raw = re.sub(r"\s+", " ", raw).strip()
    return f"{category}:{raw[:80]}"


def _severity_from(sev: int | None, category: str) -> int:
    if sev is not None:
        return int(sev)
    high = {"sql_injection", "command_injection", "deserialization", "ssti", "ssrf"}
    return 1 if category in high else 2


def from_eve(rec: dict) -> dict | None:
    """Map a Suricata EVE JSON record to the internal schema. Returns None to skip."""
    et = rec.get("event_type")
    if et not in ("alert", "http", "flow", "fileinfo"):
        return None
    http = rec.get("http", {}) or {}
    alert = rec.get("alert", {}) or {}
    url = http.get("url")
    payload_text = rec.get("payload_printable") or http.get("http_request_body_printable")
    payload_b64 = rec.get("payload")  # EVE 'payload' is base64 when present
    signature = alert.get("signature")
    category = classify_technique(url, payload_text, signature)

    ev = {
        "ts": canonical_ts(rec.get("timestamp")),
        "source": "suricata",
        "src_ip": rec.get("src_ip"),
        "src_port": rec.get("src_port"),
        "dest_ip": rec.get("dest_ip"),
        "dest_port": rec.get("dest_port"),
        "proto": rec.get("proto"),
        "flow_id": str(rec.get("flow_id")) if rec.get("flow_id") is not None else None,
        "tx_id": str(http.get("tx_id")) if http.get("tx_id") is not None else None,
        "event_type": et,
        "category": category,
        "signature": signature,
        "signature_id": alert.get("signature_id"),
        "severity": _severity_from(alert.get("severity"), category),
        "http_method": http.get("http_method"),
        "http_url": url,
        "http_status": http.get("status"),
        "http_host": http.get("hostname"),
        "payload": _bound(payload_text),
        "payload_b64": payload_b64 if isinstance(payload_b64, str) else None,
        "fingerprint": fingerprint(category, url, payload_text),
    }
    ev["outcome"] = _event_outcome_hint(ev, rec)
    return ev


def from_access_log(row: dict) -> dict:
    """Map a structured HTTP access-log row (dict) to the internal schema."""
    url = row.get("url") or row.get("path")
    payload_text = row.get("body") or row.get("query")
    category = classify_technique(url, payload_text, None)
    ev = {
        "ts": canonical_ts(row.get("ts")),
        "source": row.get("source", "accesslog"),
        "src_ip": row.get("src_ip") or row.get("client"),
        "src_port": row.get("src_port"),
        "dest_ip": row.get("dest_ip") or row.get("server"),
        "dest_port": row.get("dest_port"),
        "proto": row.get("proto", "tcp"),
        "flow_id": row.get("flow_id"),
        "tx_id": row.get("tx_id"),
        "event_type": "http",
        "category": category,
        "signature": row.get("signature"),
        "signature_id": None,
        "severity": _severity_from(None, category),
        "http_method": row.get("method"),
        "http_url": url,
        "http_status": row.get("status"),
        "http_host": row.get("host"),
        "payload": _bound(payload_text),
        "payload_b64": None,
        "fingerprint": fingerprint(category, url, payload_text),
    }
    # access logs may carry explicit app-level proof markers for the test harness
    ev["outcome"] = _event_outcome_hint(ev, row)
    return ev


def _bound(text, limit: int = 8192) -> str | None:
    if text is None:
        return None
    s = str(text)
    return s[:limit]


def _event_outcome_hint(ev: dict, rec: dict) -> str:
    """Per-event outcome signal (not final). Final outcome set by classify.py."""
    status = ev.get("http_status")
    # A control explicitly blocked it.
    if status in (403, 406, 429) or (rec.get("alert", {}) or {}).get("action") == "blocked":
        return "blocked"
    # Explicit, attributable application-level proof from an instrumented service.
    proof = rec.get("app_proof") or rec.get("proof")
    if proof:
        return "confirmed"
    return "attempted"
