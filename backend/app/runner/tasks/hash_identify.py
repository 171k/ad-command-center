#!/usr/bin/env python3
"""Identify likely hash types from a string (length + charset heuristics).

Reads {"value": "..."} as JSON on stdin; writes {"candidates":[...]} on stdout.
Pure, deterministic, offline. No network, no file access.
"""
import json
import re
import sys

HEX = re.compile(r"^[a-fA-F0-9]+$")
B64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def identify(v: str) -> list[str]:
    v = v.strip()
    out = []
    n = len(v)
    if HEX.match(v):
        out += {
            32: ["MD5", "NTLM", "MD4"],
            40: ["SHA-1"],
            56: ["SHA-224"],
            64: ["SHA-256"],
            96: ["SHA-384"],
            128: ["SHA-512"],
        }.get(n, [])
    if v.startswith("$2a$") or v.startswith("$2b$") or v.startswith("$2y$"):
        out.append("bcrypt")
    if v.startswith("$1$"):
        out.append("md5crypt")
    if v.startswith("$6$"):
        out.append("sha512crypt")
    if v.startswith("$5$"):
        out.append("sha256crypt")
    if v.startswith("$argon2"):
        out.append("Argon2")
    if ":" in v and HEX.match(v.split(":")[0] or "x"):
        out.append("possible salted hash (hash:salt)")
    if not out and B64.match(v) and n % 4 == 0:
        out.append("possible Base64-encoded data (not a hash)")
    return out or ["unknown"]


def main():
    args = json.loads(sys.stdin.read() or "{}")
    value = str(args.get("value", ""))[:512]
    print(json.dumps({"value_len": len(value), "candidates": identify(value)}))


if __name__ == "__main__":
    main()
