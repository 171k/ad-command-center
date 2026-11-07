"""Deterministic encoder/decoder utilities. Pure functions, no I/O, no network."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import urllib.parse
from datetime import datetime, timezone


def b64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def b64_decode(text: str) -> str:
    # tolerate missing padding
    pad = "=" * (-len(text) % 4)
    return base64.b64decode(text + pad).decode("utf-8", "replace")


def url_encode(text: str) -> str:
    return urllib.parse.quote_plus(text)


def url_decode(text: str) -> str:
    return urllib.parse.unquote_plus(text)


def hex_encode(text: str) -> str:
    return text.encode("utf-8").hex()


def hex_decode(text: str) -> str:
    return bytes.fromhex(text.strip().replace(" ", "")).decode("utf-8", "replace")


def hashes(text: str) -> dict:
    data = text.encode("utf-8")
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


def json_pretty(text: str) -> str:
    return json.dumps(json.loads(text), indent=2, ensure_ascii=False, sort_keys=True)


def jwt_decode(token: str) -> dict:
    """Decode JWT header+payload WITHOUT verifying the signature.

    The result explicitly states that the signature is NOT validated, so this
    is never mistaken for authentication.
    """
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("Not a JWT (expected header.payload.signature).")

    def _seg(seg: str):
        pad = "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg + pad))

    return {
        "header": _seg(parts[0]),
        "payload": _seg(parts[1]),
        "signature_present": len(parts) >= 3 and bool(parts[2]),
        "signature_verified": False,
        "warning": "Signature is NOT verified. This decodes claims only; do not treat as authenticated.",
    }


def timestamp_convert(value: str) -> dict:
    v = value.strip()
    try:
        ts = float(v)
        if ts > 1e12:  # milliseconds
            ts /= 1000.0
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return {"epoch": ts, "iso_utc": dt.isoformat(), "human": dt.strftime("%Y-%m-%d %H:%M:%S UTC")}
    except ValueError:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        return {"iso": dt.isoformat(), "epoch": dt.timestamp()}


OPERATIONS = {
    "b64_encode": b64_encode, "b64_decode": b64_decode,
    "url_encode": url_encode, "url_decode": url_decode,
    "hex_encode": hex_encode, "hex_decode": hex_decode,
    "json_pretty": json_pretty,
}


def run(op: str, text: str) -> dict:
    if op == "hashes":
        return {"ok": True, "result": hashes(text)}
    if op == "jwt_decode":
        return {"ok": True, "result": jwt_decode(text)}
    if op == "timestamp":
        return {"ok": True, "result": timestamp_convert(text)}
    fn = OPERATIONS.get(op)
    if not fn:
        raise ValueError(f"Unknown operation: {op}")
    try:
        return {"ok": True, "result": fn(text)}
    except (binascii.Error, ValueError, UnicodeDecodeError, json.JSONDecodeError) as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
