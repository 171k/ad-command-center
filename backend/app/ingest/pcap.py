"""PCAP ingestion via tshark (reuse over reinvention, no custom packet parser).

We shell out to the trusted `tshark` binary to extract HTTP request metadata,
then feed it through the normal normalization + correlation path. If tshark is
not installed we fail clearly rather than pretending to parse packets.

Safety: the uploaded file is validated by magic bytes, size-capped, processed
with a timeout and never executed. Packet payloads are stored as escaped text.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

PCAP_MAGICS = (
    b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",      # pcap (big/little endian)
    b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",      # pcap nanosecond
    b"\x0a\x0d\x0d\x0a",                             # pcapng
)


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


def validate_magic(first_bytes: bytes) -> bool:
    return any(first_bytes.startswith(m) for m in PCAP_MAGICS)


def extract_http(path: Path, timeout: int = 60, limit: int = 20000) -> list[dict]:
    """Return access-log-shaped rows for HTTP requests found in the capture."""
    if not tshark_available():
        raise RuntimeError("tshark is not installed on the server; cannot parse PCAP.")
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst", "tcp.dstport",
        "http.request.method", "http.host", "http.request.full_uri",
        "http.request.uri.query", "http.response.code",
    ]
    cmd = ["tshark", "-r", str(path), "-Y", "http.request", "-T", "fields", "-E", "separator=\t"]
    for f in fields:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed: {proc.stderr[:200]}")
    rows: list[dict] = []
    for line in proc.stdout.splitlines()[:limit]:
        parts = line.split("\t")
        if len(parts) < 9:
            parts += [""] * (9 - len(parts))
        ts, src, dst, dport, method, host, uri, query, _code = parts[:9]
        if not method:
            continue
        rows.append({
            "ts": _epoch_to_iso(ts),
            "source": "pcap",
            "src_ip": src or None,
            "dest_ip": dst or None,
            "dest_port": int(dport) if dport.isdigit() else None,
            "method": method or None,
            "host": host or None,
            "url": uri or None,
            "query": query or None,
            "proto": "tcp",
        })
    return rows


def _epoch_to_iso(epoch: str) -> str | None:
    try:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError):
        return None
