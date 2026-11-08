"""Sandboxed executor for allowlisted local tasks.

Security properties:
  - No shell, ever: the child is spawned as an argv list
    [python, -I, <bundled script>]; `-I` isolates it (ignores env vars, user
    site and the CWD on sys.path). Arguments are passed as JSON on STDIN, so
    nothing attacker-controlled is ever placed on a command line.
  - Only allowlisted task scripts can run (registry.BY_ID); the resolved script
    path is verified to stay inside the tasks directory.
  - Scrubbed, minimal environment (no inherited secrets); fresh temp CWD.
  - POSIX resource limits via preexec_fn: CPU time, address space (memory),
    max file size, open files, no core dumps; new session for group-kill.
  - Hard wall-clock timeout; the whole process group is killed on timeout.
  - Output is truncated to a bounded size.
  - A semaphore caps concurrent executions.
  - The feature is gated off by default (enable_task_execution) and never runs
    a user-supplied command, only the fixed utilities in the registry.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import threading
import time

from .. import db
from ..config import get_settings
from . import registry

_IS_POSIX = os.name == "posix"
_sema = threading.BoundedSemaphore(max(1, get_settings().worker_concurrency))

_CLEAN_ENV = {
    "PATH": "/usr/bin:/bin" if _IS_POSIX else os.environ.get("PATH", ""),
    "LC_ALL": "C",
    "LANG": "C",
    "PYTHONUNBUFFERED": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
}


def _preexec(task: "registry.Task"):
    if not _IS_POSIX:
        return None
    import resource

    def _apply():
        os.setsid()  # own process group -> killable as a unit
        cpu = task.cpu_s
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
        mem = task.mem_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 20, 1 << 20))  # 1MB writes
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    return _apply


class RunnerDisabled(Exception):
    pass


class Busy(Exception):
    pass


def run_task(task_id: str, raw_args: dict, label: str | None) -> dict:
    s = get_settings()
    if not s.enable_task_execution:
        raise RunnerDisabled(
            "Controlled task execution is disabled. Enable ADCC_ENABLE_TASK_EXECUTION=1 "
            "(only behind HTTPS) to turn on the allowlisted local-utility runner."
        )
    task = registry.BY_ID.get(task_id)
    if not task:
        raise registry.ValidationError(f"unknown task: {task_id}")
    args = registry.validate_args(task, raw_args)

    if not _sema.acquire(timeout=2):
        raise Busy("Runner is at capacity; try again shortly.")

    cur = db.execute(
        "INSERT INTO executions(kind, status, label, started_at) "
        "VALUES (?, 'running', ?, datetime('now'))",
        (f"task:{task_id}", label),
    )
    exec_id = cur.lastrowid
    start = time.perf_counter()
    try:
        import json as _json
        payload = _json.dumps(args)
        with tempfile.TemporaryDirectory() as cwd:
            proc = subprocess.Popen(
                [sys.executable, "-I", str(task.script_path())],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=_CLEAN_ENV, cwd=cwd, text=True,
                preexec_fn=_preexec(task) if _IS_POSIX else None,
                creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if not _IS_POSIX and hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP") else 0),
            )
            try:
                out, err = proc.communicate(input=payload, timeout=task.timeout_s)
                status = "done" if proc.returncode == 0 else "error"
                rc = proc.returncode
            except subprocess.TimeoutExpired:
                _kill(proc)
                out, err = _drain(proc)
                status, rc = "timeout", None
                err = (err or "") + f"\n[killed after {task.timeout_s}s timeout]"
        out = (out or "")[: task.max_output_bytes]
        err = (err or "")[: task.max_output_bytes]
        dur = (time.perf_counter() - start) * 1000
        db.execute(
            "UPDATE executions SET status=?, exit_code=?, stdout=?, stderr=?, "
            "duration_ms=?, finished_at=datetime('now') WHERE id=?",
            (status, rc, out, err, dur, exec_id),
        )
        return {
            "id": exec_id, "task_id": task_id, "status": status, "exit_code": rc,
            "stdout": out, "stderr": err, "duration_ms": round(dur, 1),
        }
    except Exception as e:
        db.execute("UPDATE executions SET status='error', stderr=?, finished_at=datetime('now') WHERE id=?",
                   (str(e)[:500], exec_id))
        raise
    finally:
        _sema.release()


def _kill(proc: subprocess.Popen):
    try:
        if _IS_POSIX:
            os.killpg(os.getpgid(proc.pid), 9)
        else:
            proc.kill()
    except (ProcessLookupError, OSError):
        pass


def _drain(proc: subprocess.Popen):
    try:
        return proc.communicate(timeout=2)
    except Exception:
        return "", ""
