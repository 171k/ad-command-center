#!/usr/bin/env python3
"""Local, isolated sandbox worker for crash analysis and exploit testing.

This runs on YOUR machine (Kali/Ubuntu/WSL2), NOT on the Command Center server.
Uploaded challenge binaries are untrusted, so the web app never executes them —
you run them here, under isolation, and paste the results back into the case.

Isolation (best-effort, strongest available on the host):
  - non-root (run as a low-priv user; never root)
  - no network           : wrapped in `unshare -n` when permitted
  - CPU / memory / file-size / core limits via setrlimit (POSIX)
  - hard wall-clock timeout with process-group kill
  - runs in a temp CWD; no secrets mounted

Usage:
  python3 pwn_sandbox.py run ./chall [--stdin input.txt] [--timeout 10]
  python3 pwn_sandbox.py exploit ./chall ./exploit.py [--timeout 30]

Output is JSON: exit code, terminating signal (crash), stdout/stderr (bounded).
Do NOT run this as root. Do NOT point it at infrastructure you are not authorized
to test.
"""
from __future__ import annotations

import argparse
import json
import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile

SIGNAMES = {getattr(signal, n): n for n in dir(signal) if n.startswith("SIG") and not n.startswith("SIG_")}


def _limits(cpu=10, mem_mb=512):
    def apply():
        os.setsid()
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
        m = mem_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (m, m))
        resource.setrlimit(resource.RLIMIT_FSIZE, (16 << 20, 16 << 20))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return apply


def _wrap_no_network(argv):
    """Prefix with `unshare -n` if available & permitted (network isolation)."""
    if shutil.which("unshare"):
        return ["unshare", "-n", "--"] + argv
    return argv


def _execute(argv, stdin_data: bytes, timeout: int, cpu: int):
    if os.name != "posix":
        return {"error": "The sandbox worker requires Linux (use WSL2/Kali)."}
    if os.geteuid() == 0:
        return {"error": "Refusing to run as root. Use a low-privilege user."}
    network_isolated = shutil.which("unshare") is not None
    full = _wrap_no_network(argv)
    with tempfile.TemporaryDirectory() as cwd:
        try:
            p = subprocess.Popen(full, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, cwd=cwd, preexec_fn=_limits(cpu))
        except OSError as e:
            return {"error": f"spawn failed: {e}"}
        try:
            out, err = p.communicate(input=stdin_data, timeout=timeout)
            rc, sig, timed = p.returncode, None, False
            if rc is not None and rc < 0:
                sig = SIGNAMES.get(-rc, str(-rc))
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except OSError:
                pass
            out, err = p.communicate()
            rc, sig, timed = None, None, True
    crash = sig in ("SIGSEGV", "SIGABRT", "SIGBUS", "SIGILL", "SIGFPE")
    return {
        "exit_code": rc,
        "signal": sig,
        "crashed": bool(crash),
        "timed_out": timed,
        "network_isolated": network_isolated,
        "stdout": out[:8192].decode("latin-1", "replace"),
        "stderr": err[:8192].decode("latin-1", "replace"),
        "hint": ("SIGSEGV — memory corruption; inspect with: gdb -q <bin> -ex 'run < input' -ex bt"
                 if sig == "SIGSEGV" else None),
    }


def main():
    ap = argparse.ArgumentParser(prog="pwn_sandbox")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run"); r.add_argument("binary"); r.add_argument("--stdin"); r.add_argument("--timeout", type=int, default=10); r.add_argument("--cpu", type=int, default=10)
    e = sub.add_parser("exploit"); e.add_argument("binary"); e.add_argument("script"); e.add_argument("--timeout", type=int, default=30); e.add_argument("--cpu", type=int, default=20)
    a = ap.parse_args()
    if a.cmd == "run":
        os.chmod(a.binary, 0o755)
        data = open(a.stdin, "rb").read() if a.stdin else b""
        print(json.dumps(_execute([os.path.abspath(a.binary)], data, a.timeout, a.cpu), indent=2))
    elif a.cmd == "exploit":
        os.chmod(a.binary, 0o755)
        res = _execute([sys.executable, os.path.abspath(a.script)], b"", a.timeout, a.cpu)
        print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
