"""Deterministic pwn helper utilities (no execution, no network, no pwntools dep).

- cyclic / cyclic_find: pwntools-compatible De Bruijn pattern + offset lookup.
- pack/unpack: architecture-aware integer packing.
- find_gadgets: byte-signature ROP gadget search over executable segments.
- exploit_template: a ready-to-edit pwntools exploit skeleton.
"""
from __future__ import annotations

import string
import struct

from .elf import PF_X, ELF

_ALPHA = string.ascii_lowercase


def _de_bruijn(alphabet: str = _ALPHA, n: int = 4):
    k = len(alphabet)
    a = [0] * k * n
    seq = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                seq.extend(a[1: p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    while True:
        for i in seq:
            yield alphabet[i]


def cyclic(length: int, n: int = 4) -> bytes:
    g = _de_bruijn(n=n)
    return bytes(ord(next(g)) for _ in range(length))


def cyclic_find(sub, n: int = 4) -> int:
    """Return the offset of `sub` (str/bytes/int) within the cyclic pattern or -1."""
    if isinstance(sub, int):
        sub = struct.pack("<I", sub)  # treat as little-endian 32-bit leak
    if isinstance(sub, str):
        sub = sub.encode()
    sub = sub.rstrip(b"\x00")
    if len(sub) < 1:
        return -1
    pat = cyclic(len(sub) + 0x4000, n=n)  # generous window
    idx = pat.find(sub)
    return idx


def pack(value: int, bits: int = 64, endian: str = "little", signed: bool = False) -> str:
    nbytes = bits // 8
    try:
        return value.to_bytes(nbytes, endian, signed=signed).hex()
    except OverflowError:
        return (value & ((1 << bits) - 1)).to_bytes(nbytes, endian).hex()


def unpack(hexstr: str, bits: int = 64, endian: str = "little", signed: bool = False) -> int:
    raw = bytes.fromhex(hexstr.replace("0x", "").replace(" ", ""))
    raw = (raw + b"\x00" * (bits // 8))[: bits // 8]
    return int.from_bytes(raw, endian, signed=signed)


# Common ROP gadget signatures (x86 / x86-64).
GADGET_SIGS = {
    "ret": b"\xc3",
    "pop rdi; ret": b"\x5f\xc3",
    "pop rsi; ret": b"\x5e\xc3",
    "pop rdx; ret": b"\x5a\xc3",
    "pop rax; ret": b"\x58\xc3",
    "pop rbx; ret": b"\x5b\xc3",
    "pop rcx; ret": b"\x59\xc3",
    "pop rbp; ret": b"\x5d\xc3",
    "pop rsp; ret": b"\x5c\xc3",
    "pop rsi; pop r15; ret": b"\x5e\x41\x5f\xc3",
    "pop rdi; pop rbp; ret": b"\x5f\x5d\xc3",
    "leave; ret": b"\xc9\xc3",
    "syscall": b"\x0f\x05",
    "syscall; ret": b"\x0f\x05\xc3",
    "int 0x80": b"\xcd\x80",
    "jmp rsp": b"\xff\xe4",
    "call rsp": b"\xff\xd4",
}


def find_gadgets(data: bytes, wanted: list[str] | None = None, limit_per: int = 20) -> dict:
    """Search executable segments for known gadget byte-signatures; return vaddrs."""
    e = ELF(data)
    exec_segs = [p for p in e.phdrs if (p["flags"] & PF_X) and p["filesz"]]
    sigs = {k: v for k, v in GADGET_SIGS.items() if (not wanted or k in wanted)}
    results: dict[str, list[str]] = {}
    for name, sig in sigs.items():
        hits = []
        for seg in exec_segs:
            blob = data[seg["offset"]: seg["offset"] + seg["filesz"]]
            start = 0
            while len(hits) < limit_per:
                i = blob.find(sig, start)
                if i == -1:
                    break
                vaddr = seg["vaddr"] + i
                hits.append(hex(vaddr))
                start = i + 1
        if hits:
            results[name] = hits
    return {"pie": e.etype == "DYN", "note": "addresses are file-absolute; for PIE add the runtime base", "gadgets": results}


def exploit_template(binary_name: str, arch: str = "amd64", host: str = "", port: int = 0) -> str:
    remote = (f"    if args.REMOTE:\n        return remote('{host}', {port})\n" if host else
              "    if args.REMOTE:\n        return remote(HOST, PORT)\n")
    return f'''#!/usr/bin/env python3
from pwn import *

context.binary = exe = ELF('./{binary_name}')
context.arch = '{arch}'
context.terminal = ['tmux', 'splitw', '-h']

HOST, PORT = '{host or "CHANGE_ME"}', {port or 0}

def conn():
{remote}    return process(exe.path)

def main():
    io = conn()

    # === offset ===
    # io.sendline(cyclic(200))   # then find the crash offset
    OFFSET = 0  # TODO

    # === rop ===
    rop = ROP(exe)
    # rop.raw(rop.ret)          # stack alignment
    # rop.call(exe.sym.get('win', 0))

    payload = flat({{OFFSET: rop.chain()}})
    io.sendline(payload)
    io.interactive()

if __name__ == '__main__':
    main()
'''
