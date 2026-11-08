"""Minimal, dependency-free ELF parser + checksec.

Parses (never executes) an ELF to report format, architecture, and exploit
mitigations (NX, PIE, RELRO, stack canary, Fortify). Pure-Python so it works on
the 4GB VM without binutils/pwntools; readelf/objdump are used only to *enrich*
symbol/disassembly views when present (see analysis.py).
"""
from __future__ import annotations

import struct

EM = {
    0x03: "x86", 0x3E: "amd64", 0x28: "arm", 0xB7: "aarch64",
    0x08: "mips", 0x14: "ppc", 0x15: "ppc64", 0xF3: "riscv",
}
ET = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}

PT_INTERP, PT_DYNAMIC, PT_GNU_STACK, PT_GNU_RELRO = 3, 2, 0x6474E551, 0x6474E552
PF_X = 1
DT_NULL, DT_NEEDED, DT_BIND_NOW, DT_FLAGS, DT_FLAGS_1 = 0, 1, 24, 30, 0x6FFFFFFB
DF_BIND_NOW, DF_1_NOW = 0x08, 0x00000001


class NotELF(Exception):
    pass


class ELF:
    def __init__(self, data: bytes):
        if len(data) < 64 or data[:4] != b"\x7fELF":
            raise NotELF("not an ELF file")
        self.data = data
        self.ei_class = data[4]           # 1=32, 2=64
        self.ei_data = data[5]            # 1=LE, 2=BE
        self.is64 = self.ei_class == 2
        self.end = "<" if self.ei_data == 1 else ">"
        self._parse_header()
        self._parse_phdrs()
        self._parse_sections()

    # ---- header ----
    def _u(self, fmt, off):
        sz = struct.calcsize(self.end + fmt)
        return struct.unpack_from(self.end + fmt, self.data, off)[0] if off + sz <= len(self.data) else 0

    def _parse_header(self):
        self.e_type = self._u("H", 16)
        self.e_machine = self._u("H", 18)
        if self.is64:
            self.e_entry = self._u("Q", 24); self.e_phoff = self._u("Q", 32); self.e_shoff = self._u("Q", 40)
            self.e_phentsize = self._u("H", 54); self.e_phnum = self._u("H", 56)
            self.e_shentsize = self._u("H", 58); self.e_shnum = self._u("H", 60); self.e_shstrndx = self._u("H", 62)
        else:
            self.e_entry = self._u("I", 24); self.e_phoff = self._u("I", 28); self.e_shoff = self._u("I", 32)
            self.e_phentsize = self._u("H", 42); self.e_phnum = self._u("H", 44)
            self.e_shentsize = self._u("H", 46); self.e_shnum = self._u("H", 48); self.e_shstrndx = self._u("H", 50)
        self.arch = EM.get(self.e_machine, f"machine-0x{self.e_machine:x}")
        self.bits = 64 if self.is64 else 32
        self.etype = ET.get(self.e_type, str(self.e_type))

    def _parse_phdrs(self):
        self.phdrs = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            if self.is64:
                p_type = self._u("I", off); p_flags = self._u("I", off + 4)
                p_offset = self._u("Q", off + 8); p_vaddr = self._u("Q", off + 16); p_filesz = self._u("Q", off + 32)
            else:
                p_type = self._u("I", off); p_offset = self._u("I", off + 4)
                p_vaddr = self._u("I", off + 8); p_filesz = self._u("I", off + 16); p_flags = self._u("I", off + 24)
            self.phdrs.append({"type": p_type, "flags": p_flags, "offset": p_offset, "vaddr": p_vaddr, "filesz": p_filesz})

    def _parse_sections(self):
        self.sections = {}
        if not self.e_shoff or not self.e_shnum:
            return
        # section header string table
        shstr_off = self.e_shoff + self.e_shstrndx * self.e_shentsize
        str_off = self._u("Q" if self.is64 else "I", shstr_off + (24 if self.is64 else 16))
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            name_idx = self._u("I", off)
            if self.is64:
                sh_off = self._u("Q", off + 24); sh_size = self._u("Q", off + 32); sh_entsize = self._u("Q", off + 56)
                sh_link = self._u("I", off + 40)
            else:
                sh_off = self._u("I", off + 16); sh_size = self._u("I", off + 20); sh_entsize = self._u("I", off + 36)
                sh_link = self._u("I", off + 24)
            name = self._cstr(str_off + name_idx)
            self.sections[name] = {"offset": sh_off, "size": sh_size, "entsize": sh_entsize, "link": sh_link}

    def _cstr(self, off):
        end = self.data.find(b"\x00", off)
        return self.data[off:end].decode("latin-1", "replace") if end != -1 else ""

    # ---- dynamic + symbols ----
    def _dynamic(self):
        out = []
        for ph in self.phdrs:
            if ph["type"] == PT_DYNAMIC:
                off = ph["offset"]; esz = 16 if self.is64 else 8
                for k in range(0, ph["filesz"], esz):
                    if self.is64:
                        tag = self._u("q", off + k); val = self._u("Q", off + k + 8)
                    else:
                        tag = self._u("i", off + k); val = self._u("I", off + k + 4)
                    out.append((tag, val))
                    if tag == DT_NULL:
                        break
        return out

    def dynamic_symbols(self) -> list[str]:
        sec = self.sections.get(".dynsym") or self.sections.get(".symtab")
        if not sec or not sec["entsize"]:
            return []
        strsec_idx = sec["link"]
        # resolve the linked string table by index
        str_off = None
        for i, (name, s) in enumerate(self.sections.items()):
            if i == strsec_idx:
                str_off = s["offset"]; break
        if str_off is None:
            str_off = (self.sections.get(".dynstr") or self.sections.get(".strtab") or {}).get("offset")
        if str_off is None:
            return []
        names = []
        n = sec["size"] // sec["entsize"]
        for i in range(min(n, 5000)):
            e = sec["offset"] + i * sec["entsize"]
            name_idx = self._u("I", e)
            if name_idx:
                names.append(self._cstr(str_off + name_idx))
        return [x for x in names if x]


def checksec(data: bytes) -> dict:
    e = ELF(data)
    syms = set(e.dynamic_symbols())

    nx = any(p["type"] == PT_GNU_STACK for p in e.phdrs)
    if nx:
        nx = all((p["flags"] & PF_X) == 0 for p in e.phdrs if p["type"] == PT_GNU_STACK)
    has_interp = any(p["type"] == PT_INTERP for p in e.phdrs)
    pie = (e.etype == "DYN" and has_interp)

    dyn = dict(e._dynamic())
    bind_now = (DT_BIND_NOW in dyn) or bool(dyn.get(DT_FLAGS, 0) & DF_BIND_NOW) or bool(dyn.get(DT_FLAGS_1, 0) & DF_1_NOW)
    has_relro = any(p["type"] == PT_GNU_RELRO for p in e.phdrs)
    relro = "Full" if (has_relro and bind_now) else "Partial" if has_relro else "No"

    canary = "__stack_chk_fail" in syms or "__stack_chk_guard" in syms
    fortify = any(s.endswith("_chk") for s in syms)

    return {
        "format": "ELF",
        "arch": e.arch,
        "bits": e.bits,
        "endian": "little" if e.ei_data == 1 else "big",
        "type": e.etype,
        "entry": hex(e.e_entry),
        "nx": bool(nx),
        "pie": bool(pie),
        "relro": relro,
        "canary": bool(canary),
        "fortify": bool(fortify),
        "stripped": ".symtab" not in e.sections,
        "libc_needed": _needed_libs(e),
        "symbol_count": len(syms),
    }


def _needed_libs(e: "ELF") -> list[str]:
    # DT_NEEDED values are offsets into .dynstr
    dynstr = e.sections.get(".dynstr")
    if not dynstr:
        return []
    libs = []
    for tag, val in e._dynamic():
        if tag == DT_NEEDED:
            libs.append(e._cstr(dynstr["offset"] + val))
    return libs
