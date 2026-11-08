"""Curated catalog metadata for well-known open-source CTF/security tools.

This seeds *metadata* only (descriptions, licenses, provenance, per-OS install
guidance). Binary artifacts are uploaded by an admin (see the Tools admin API /
`adtools`), so licenses and supply-chain integrity are reviewed per artifact and
nothing is blindly mirrored. Install commands that reference pip/apt are for when
those are reachable; the offline bundle covers the fully-air-gapped case.
"""
from __future__ import annotations

import json

from .. import db

CATALOG = [
    # ---- Binary Exploitation ----
    {"slug": "pwntools", "name": "pwntools", "category": "Binary Exploitation",
     "version": "4.13.1", "license": "MIT", "provenance": "https://github.com/Gallopsled/pwntools",
     "description": "CTF exploitation framework: ELF/ROP, tubes, shellcode, packing.",
     "os": ["kali", "ubuntu", "wsl2"], "deps": ["python3", "pip"],
     "install": {"kali": "pip install --user pwntools==4.13.1", "ubuntu": "pip install --user pwntools==4.13.1",
                 "wsl2": "pip install --user pwntools==4.13.1", "windows": "pip install pwntools (limited on native Windows; use WSL2)"},
     "tags": ["pwn", "rop", "exploit"]},
    {"slug": "ropper", "name": "ropper", "category": "Binary Exploitation",
     "version": "1.13.8", "license": "BSD-3-Clause", "provenance": "https://github.com/sashs/Ropper",
     "description": "ROP gadget finder and chain builder across architectures.",
     "os": ["kali", "ubuntu", "wsl2", "windows"], "deps": ["python3", "pip"],
     "install": {"kali": "pip install --user ropper", "ubuntu": "pip install --user ropper",
                 "wsl2": "pip install --user ropper", "windows": "pip install ropper"},
     "tags": ["rop", "gadgets"]},
    {"slug": "one-gadget", "name": "one_gadget", "category": "Binary Exploitation",
     "version": "1.9.0", "license": "MIT", "provenance": "https://github.com/david942j/one_gadget",
     "description": "Find one-shot execve('/bin/sh') gadgets in libc.",
     "os": ["kali", "ubuntu", "wsl2"], "deps": ["ruby"],
     "install": {"kali": "gem install one_gadget", "ubuntu": "gem install one_gadget", "wsl2": "gem install one_gadget"},
     "tags": ["libc", "one_gadget"]},
    {"slug": "pwndbg", "name": "pwndbg", "category": "Binary Exploitation",
     "version": "2024.08.29", "license": "MIT", "provenance": "https://github.com/pwndbg/pwndbg",
     "description": "GDB plugin for exploit development (heap, telescope, context).",
     "os": ["kali", "ubuntu", "wsl2"], "deps": ["gdb", "python3"],
     "install": {"kali": "unpack the hosted bundle, then ./setup.sh", "ubuntu": "unpack the hosted bundle, then ./setup.sh"},
     "tags": ["gdb", "debug"]},
    # ---- Reverse Engineering ----
    {"slug": "radare2", "name": "radare2", "category": "Reverse Engineering",
     "version": "5.9.4", "license": "LGPL-3.0", "provenance": "https://github.com/radareorg/radare2",
     "description": "Reverse-engineering framework: disassembly, debugging, analysis.",
     "os": ["kali", "ubuntu", "wsl2", "windows"], "deps": [],
     "install": {"kali": "apt install radare2", "ubuntu": "apt install radare2", "wsl2": "apt install radare2",
                 "windows": "download the hosted Windows build"}, "tags": ["disasm", "re"]},
    {"slug": "binwalk", "name": "binwalk", "category": "Reverse Engineering",
     "version": "2.3.4", "license": "MIT", "provenance": "https://github.com/ReFirmLabs/binwalk",
     "description": "Firmware/file carving and entropy analysis.",
     "os": ["kali", "ubuntu", "wsl2"], "deps": ["python3"],
     "install": {"kali": "apt install binwalk", "ubuntu": "apt install binwalk", "wsl2": "apt install binwalk"},
     "tags": ["forensics", "carving"]},
    # ---- Web Security ----
    {"slug": "sqlmap", "name": "sqlmap", "category": "Web Security",
     "version": "1.8.9", "license": "GPL-2.0", "provenance": "https://github.com/sqlmapproject/sqlmap",
     "description": "Automated SQL injection detection and exploitation.",
     "os": ["kali", "ubuntu", "wsl2"], "deps": ["python3"],
     "install": {"kali": "apt install sqlmap", "ubuntu": "apt install sqlmap", "wsl2": "unpack hosted bundle; python sqlmap.py"},
     "tags": ["web", "sqli"]},
    {"slug": "ffuf", "name": "ffuf", "category": "Web Security",
     "version": "2.1.0", "license": "MIT", "provenance": "https://github.com/ffuf/ffuf",
     "description": "Fast web fuzzer (content/parameter discovery). Single static binary.",
     "os": ["kali", "ubuntu", "wsl2", "windows"], "deps": [],
     "install": {"kali": "download hosted binary -> chmod +x -> ~/.local/bin", "windows": "download hosted ffuf.exe"},
     "tags": ["web", "fuzzing"]},
    # ---- Cryptography ----
    {"slug": "cyberchef", "name": "CyberChef", "category": "Cryptography",
     "version": "10.19.0", "license": "Apache-2.0", "provenance": "https://github.com/gchq/CyberChef",
     "description": "Offline data-transform toolkit (single self-contained HTML). Runs in any browser, no network.",
     "os": ["kali", "ubuntu", "wsl2", "windows"], "deps": [],
     "install": {"kali": "download hosted CyberChef.html -> open in browser", "windows": "download CyberChef.html -> open in browser"},
     "tags": ["crypto", "encoding", "offline"]},
    {"slug": "john", "name": "John the Ripper", "category": "Cryptography",
     "version": "1.9.0-jumbo", "license": "GPL-2.0", "provenance": "https://github.com/openwall/john",
     "description": "Password hash cracker (jumbo). Many formats.",
     "os": ["kali", "ubuntu", "wsl2"], "deps": [],
     "install": {"kali": "apt install john", "ubuntu": "apt install john"}, "tags": ["crypto", "cracking"]},
    # ---- Digital Forensics ----
    {"slug": "exiftool", "name": "ExifTool", "category": "Digital Forensics",
     "version": "12.96", "license": "Artistic/GPL", "provenance": "https://exiftool.org",
     "description": "Read/write metadata in images and many file types.",
     "os": ["kali", "ubuntu", "wsl2", "windows"], "deps": ["perl"],
     "install": {"kali": "apt install libimage-exiftool-perl", "windows": "download hosted exiftool.exe"},
     "tags": ["forensics", "metadata"]},
    # ---- Networking ----
    {"slug": "nmap", "name": "Nmap", "category": "Networking",
     "version": "7.95", "license": "NPSL", "provenance": "https://nmap.org",
     "description": "Network/service discovery and scanning. Use only on authorized targets.",
     "os": ["kali", "ubuntu", "wsl2", "windows"], "deps": [],
     "install": {"kali": "apt install nmap", "ubuntu": "apt install nmap", "windows": "download hosted nmap setup"},
     "tags": ["network", "scanning"]},
    # ---- SOC / Log Analysis ----
    {"slug": "ripgrep", "name": "ripgrep", "category": "SOC / Log Analysis",
     "version": "14.1.1", "license": "MIT/Unlicense", "provenance": "https://github.com/BurntSushi/ripgrep",
     "description": "Very fast recursive search for logs/code. Single static binary.",
     "os": ["kali", "ubuntu", "wsl2", "windows"], "deps": [],
     "install": {"kali": "apt install ripgrep", "windows": "download hosted rg.exe"}, "tags": ["logs", "search"]},
    {"slug": "jq", "name": "jq", "category": "SOC / Log Analysis",
     "version": "1.7.1", "license": "MIT", "provenance": "https://github.com/jqlang/jq",
     "description": "Command-line JSON processor (parse EVE/alerts). Single static binary.",
     "os": ["kali", "ubuntu", "wsl2", "windows"], "deps": [],
     "install": {"kali": "apt install jq", "windows": "download hosted jq.exe"}, "tags": ["json", "logs"]},
    # ---- General CTF Utilities ----
    {"slug": "pwninit", "name": "pwninit", "category": "General CTF Utilities",
     "version": "3.3.1", "license": "MIT", "provenance": "https://github.com/io12/pwninit",
     "description": "Auto-set up pwn challenge dirs: patch loader/libc, template exploit.",
     "os": ["kali", "ubuntu", "wsl2"], "deps": [],
     "install": {"kali": "download hosted binary -> chmod +x -> ~/.local/bin"}, "tags": ["pwn", "setup"]},
]


def seed_catalog(force: bool = False) -> int:
    n = 0
    for t in CATALOG:
        if not force and db.query_one("SELECT 1 FROM tools WHERE slug=?", (t["slug"],)):
            continue
        db.execute(
            "INSERT OR IGNORE INTO tools(slug,name,category,version,description,license,provenance,"
            "os_support,dependencies,install,tags) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (t["slug"], t["name"], t["category"], t["version"], t["description"], t["license"],
             t["provenance"], json.dumps(t["os"]), json.dumps(t["deps"]), json.dumps(t["install"]),
             json.dumps(t["tags"])),
        )
        n += 1
    return n
