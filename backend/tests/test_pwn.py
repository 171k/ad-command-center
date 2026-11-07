"""Pwn Solver: deterministic utilities, checksec on crafted ELFs, gadget search,
and the case upload/analysis/persistence API (acceptance criteria 4-9)."""
import struct

from app.pwn import elf
from app.pwn import pwntools_utils as pu


# ---- minimal ELF builder (enough to exercise the static parser deterministically) ----
def make_elf(etype=2, machine=0x3E, interp=True, nx=True, relro="Full", exec_payload=b"\x5f\xc3\xc3"):
    phdrs = []  # (p_type, p_flags, payload) — offsets filled below
    phdrs.append(("LOAD", 0x1, 0x5, exec_payload))            # R+X segment with gadgets
    phdrs.append(("GNU_STACK", 0x6474E551, 0x6 if nx else 0x7, b""))
    if interp:
        phdrs.append(("INTERP", 0x3, 0x4, b"/lib64/ld-linux-x86-64.so.2\x00"))
    if relro in ("Partial", "Full"):
        phdrs.append(("RELRO", 0x6474E552, 0x4, b""))
    dyn = b""
    if relro == "Full":
        dyn = struct.pack("<qQ", 24, 0) + struct.pack("<qQ", 0, 0)   # DT_BIND_NOW, DT_NULL
    elif relro == "Partial":
        dyn = struct.pack("<qQ", 0, 0)
    if dyn:
        phdrs.append(("DYNAMIC", 0x2, 0x6, dyn))

    phnum = len(phdrs)
    phoff = 64
    data_off = phoff + phnum * 56
    base = 0x400000 if etype == 2 else 0
    # assign offsets to each payload
    blobs = []
    cur = data_off
    meta = []
    for (name, ptype, flags, payload) in phdrs:
        off = cur
        vaddr = base + off
        meta.append((ptype, flags, off, vaddr, len(payload)))
        blobs.append(payload)
        cur += len(payload)
    # build ehdr
    e = bytearray(64)
    e[0:4] = b"\x7fELF"; e[4] = 2; e[5] = 1; e[6] = 1
    struct.pack_into("<H", e, 16, etype)
    struct.pack_into("<H", e, 18, machine)
    struct.pack_into("<I", e, 20, 1)
    struct.pack_into("<Q", e, 24, base + data_off)   # entry
    struct.pack_into("<Q", e, 32, phoff)
    struct.pack_into("<H", e, 52, 64)
    struct.pack_into("<H", e, 54, 56)
    struct.pack_into("<H", e, 56, phnum)
    out = bytes(e)
    for (ptype, flags, off, vaddr, sz) in meta:
        ph = struct.pack("<IIQQQQQQ", ptype, flags, off, vaddr, vaddr, sz, sz, 0x1000)
        out += ph
    for b in blobs:
        out += b
    return out


def test_cyclic_and_find():
    pat = pu.cyclic(200)
    assert len(pat) == 200
    # take a 4-byte slice at a known offset; cyclic_find must return it
    probe = pat[100:104]
    assert pu.cyclic_find(probe) == 100
    # simulate a leaked little-endian dword (EIP/RIP overwrite)
    leaked = struct.unpack("<I", pat[40:44])[0]
    assert pu.cyclic_find(leaked) == 40


def test_pack_unpack():
    assert pu.pack(0xdeadbeef, 32, "little") == "efbeadde"
    assert pu.pack(0x400000, 64, "little") == "0000400000000000"
    assert pu.unpack("efbeadde", 32, "little") == 0xdeadbeef


def test_checksec_full_protections():
    cs = elf.checksec(make_elf(etype=2, interp=True, nx=True, relro="Full"))
    assert cs["arch"] == "amd64" and cs["bits"] == 64
    assert cs["nx"] is True
    assert cs["relro"] == "Full"
    assert cs["type"] == "EXEC"
    assert cs["pie"] is False       # ET_EXEC


def test_checksec_weak_protections():
    cs = elf.checksec(make_elf(etype=3, interp=True, nx=False, relro="No"))
    assert cs["nx"] is False
    assert cs["relro"] == "No"
    assert cs["pie"] is True        # ET_DYN + interp


def test_find_gadgets():
    data = make_elf(exec_payload=b"\x90\x5f\xc3\x90\xc3\x0f\x05\xc3")
    g = pu.find_gadgets(data)["gadgets"]
    assert "pop rdi; ret" in g
    assert "ret" in g
    assert "syscall; ret" in g


def test_upload_analyze_and_persist(auth):
    client, h = auth
    binary = make_elf(etype=2, nx=True, relro="Full", exec_payload=b"\x5f\xc3\xc3")
    r = client.post("/api/pwn/cases", files={"file": ("chall", binary, "application/octet-stream")},
                    data={"name": "test-chall"}, headers=h)
    assert r.status_code == 201
    cid = r.json()["id"]
    assert r.json()["analysis"]["checksec"]["arch"] == "amd64"

    # gadgets endpoint works on the stored binary
    g = client.get(f"/api/pwn/cases/{cid}/gadgets").json()["gadgets"]
    assert "pop rdi; ret" in g

    # template + save a script
    tmpl = client.get(f"/api/pwn/cases/{cid}/template").json()["template"]
    assert "from pwn import" in tmpl
    sid = client.post(f"/api/pwn/cases/{cid}/scripts", json={"name": "exp.py", "body": tmpl}, headers=h).json()["id"]

    # survives "restart": re-read from DB
    detail = client.get(f"/api/pwn/cases/{cid}").json()
    assert detail["analysis"]["checksec"]["relro"] == "Full"
    assert any(s["id"] == sid for s in detail["scripts"])


def test_exec_is_gated_off(auth):
    client, h = auth
    st = client.get("/api/pwn/exec-status").json()
    assert st["enabled"] is False
    assert "sandbox" in st["reason"].lower()
