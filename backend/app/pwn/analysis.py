"""Static binary analysis: combines the pure-Python ELF/checksec parse with
optional binutils enrichment (file/readelf/objdump) when those are installed.
Everything here only *reads/parses* the uploaded binary, it is never executed.
"""
from __future__ import annotations

import re
import shutil
import subprocess

from . import elf


def _run(cmd: list[str], timeout: int = 15) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def extract_strings(data: bytes, min_len: int = 4, limit: int = 400) -> list[str]:
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("latin-1"))
                if len(out) >= limit:
                    break
            cur = bytearray()
    return out


_INTERESTING = re.compile(r"(/bin/sh|system|execve|/flag|flag\{|cat |setuid|gets|strcpy|printf|%n|libc|GLIBC_)", re.I)


def analyze(data: bytes, filename: str, path: str | None = None) -> dict:
    result: dict = {"filename": filename, "size": len(data)}
    try:
        cs = elf.checksec(data)
        result["checksec"] = cs
        result["format"] = "ELF"
        e = elf.ELF(data)
        result["symbols"] = sorted(set(e.dynamic_symbols()))[:300]
        result["sections"] = list(e.sections.keys())
    except elf.NotELF:
        result["format"] = "non-ELF"
        result["note"] = "Not an ELF; limited analysis. Magic: " + data[:8].hex()
    except Exception as e:  # defensive: never crash on a malformed binary
        result["format"] = "error"
        result["note"] = f"parse error: {type(e).__name__}"

    strs = extract_strings(data)
    result["strings_sample"] = strs[:120]
    result["interesting_strings"] = [s for s in strs if _INTERESTING.search(s)][:40]

    # Optional binutils enrichment (read-only), if available on this host.
    tools = {}
    if path:
        if shutil.which("file"):
            tools["file"] = _run(["file", "-b", path]).strip()
        if shutil.which("readelf"):
            tools["readelf_h"] = _run(["readelf", "-h", path])[:4000]
        if shutil.which("objdump"):
            tools["plt"] = _run(["objdump", "-d", "-j", ".plt", path])[:6000]
    result["enrichment"] = tools
    result["enrichment_available"] = bool(tools)
    return result
