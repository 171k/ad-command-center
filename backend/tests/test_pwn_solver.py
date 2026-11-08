"""Pwn Solver: vuln classification, offset estimate and script generation.

Fixtures are tiny C programs compiled with `-fno-stack-protector -no-pie`:
  ret2win    : read() overflow + a win() function   -> ret2win, offset 56
  ret2system : read() overflow + system() + /bin/sh  -> ret2system, offset 56
"""
import io
import zipfile
from pathlib import Path

import pytest

from app.pwn import solver

FIX = Path(__file__).parent / "fixtures"


def test_classify_ret2win():
    cs = {"bits": 64, "nx": True, "canary": False}
    facts = {"imports": ["read", "puts"], "symbols": {"win": 0x401156, "vuln": 0x401160},
             "got": {}, "binsh": None}
    c = solver._classify(cs, facts)
    assert c["vuln"] == "Stack buffer overflow"
    assert c["approach"] == "ret2win"
    assert "win" in c["win_functions"]
    assert "vuln" not in c["win_functions"]  # the vulnerable func is not a win


def test_classify_ret2system():
    cs = {"bits": 64, "nx": True, "canary": False}
    facts = {"imports": ["read", "system"], "symbols": {"vuln": 0x401160},
             "got": {}, "binsh": 0x402004}
    c = solver._classify(cs, facts)
    assert c["approach"] == "ret2system"
    assert "system" in c["shell_funcs"]


def test_classify_format_string():
    cs = {"bits": 64, "nx": True, "canary": True}
    facts = {"imports": ["printf"], "symbols": {}, "got": {}, "binsh": None}
    c = solver._classify(cs, facts)
    assert c["vuln"].startswith("Possible format")
    assert c["approach"] == "format-string leak/write"


@pytest.mark.skipif(not (FIX / "ret2win").exists(), reason="fixtures missing")
def test_solve_ret2win_offset_and_script():
    data = (FIX / "ret2win").read_bytes()
    r = solver.solve(data, "ret2win", str(FIX / "ret2win"))
    assert r["vuln"] == "Stack buffer overflow"
    assert r["approach"] == "ret2win"
    assert r["offset_estimate"]["value"] == 56  # buf[0x30] + saved rbp
    assert "win" in r["win_functions"]
    assert "exe.sym['win']" in r["script"]
    assert "offset = 56" in r["script"]


@pytest.mark.skipif(not (FIX / "ret2system").exists(), reason="fixtures missing")
def test_solve_ret2system_binsh_and_chain():
    data = (FIX / "ret2system").read_bytes()
    r = solver.solve(data, "ret2system", str(FIX / "ret2system"))
    assert r["approach"] == "ret2system"
    assert r["binsh_addr"] is not None
    assert r["offset_estimate"]["value"] == 56
    assert "system" in r["script"]
    assert "binsh" in r["script"]


def test_solve_rejects_non_elf():
    with pytest.raises(Exception):
        solver.solve(b"not an elf at all", "x.txt")


@pytest.mark.skipif(not (FIX / "ret2win").exists(), reason="fixtures missing")
def test_solve_endpoint(auth):
    client, headers = auth
    data = (FIX / "ret2win").read_bytes()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w"):
        pass  # (not used; upload the raw binary)
    r = client.post(
        "/api/pwn/cases",
        files={"file": ("ret2win", data, "application/octet-stream")},
        data={"name": "ret2win"},
        headers=headers,
    )
    assert r.status_code == 201
    cid = r.json()["id"]
    s = client.get(f"/api/pwn/cases/{cid}/solve", headers=headers)
    assert s.status_code == 200
    d = s.json()
    assert d["approach"] == "ret2win"
    assert d["offset_estimate"]["value"] == 56
    assert "from pwn import *" in d["script"]
