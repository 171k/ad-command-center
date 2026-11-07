"""Sandboxed runner: gate, allowlist, validation, timeout, and (POSIX) memory cap."""
import os

import pytest

from app.config import get_settings
from app.runner import executor, registry


@pytest.fixture
def enabled():
    s = get_settings()
    old = s.enable_task_execution
    s.enable_task_execution = True
    try:
        yield
    finally:
        s.enable_task_execution = old


def _run(client, headers, tid, args):
    return client.post("/api/automation/runner/run", json={"task_id": tid, "args": args}, headers=headers)


def test_disabled_by_default(auth):
    client, h = auth
    # conftest does not enable execution -> gated off
    r = _run(client, h, "hash_identify", {"value": "x"})
    assert r.status_code == 403
    assert "disabled" in r.json()["detail"].lower()


def test_allowlist_and_validation(auth, enabled):
    client, h = auth
    # real task runs
    r = _run(client, h, "hash_crack", {"hash": "5f4dcc3b5aa765d61d8327deb882cf99", "algo": "md5"})
    assert r.status_code == 200 and r.json()["status"] == "done"
    assert '"plaintext": "password"' in r.json()["stdout"]
    # not on the allowlist
    assert _run(client, h, "definitely_not_a_task", {}).status_code == 400
    # extra / unexpected arg rejected
    assert _run(client, h, "entropy", {"text": "x", "cmd": "rm -rf /"}).status_code == 400
    # bad enum rejected
    assert _run(client, h, "hash_crack", {"hash": "x", "algo": "sha9000"}).status_code == 400


def test_timeout_kills_runaway(enabled, client):
    # Register a transient probe that sleeps far past its timeout.
    probe = registry.TASKS_DIR / "_probe_sleep.py"
    probe.write_text("import time\ntime.sleep(10)\n", encoding="utf-8")
    task = registry.Task(id="_probe_sleep", title="probe", description="",
                         script="_probe_sleep.py", params=[], timeout_s=1, cpu_s=1)
    registry.BY_ID["_probe_sleep"] = task
    try:
        res = executor.run_task("_probe_sleep", {}, "test")
        assert res["status"] == "timeout"
    finally:
        registry.BY_ID.pop("_probe_sleep", None)
        probe.unlink(missing_ok=True)


@pytest.mark.skipif(os.name != "posix", reason="RLIMIT only enforced on POSIX")
def test_memory_limit_enforced(enabled, client):
    probe = registry.TASKS_DIR / "_probe_mem.py"
    probe.write_text("x = bytearray(1024*1024*1024)\nprint('allocated')\n", encoding="utf-8")
    task = registry.Task(id="_probe_mem", title="probe", description="",
                         script="_probe_mem.py", params=[], timeout_s=5, cpu_s=3, mem_mb=64)
    registry.BY_ID["_probe_mem"] = task
    try:
        res = executor.run_task("_probe_mem", {}, "test")
        # the child cannot allocate 1GB under a 64MB cap -> it fails, not 'done'
        assert res["status"] != "done"
        assert "allocated" not in res["stdout"]
    finally:
        registry.BY_ID.pop("_probe_mem", None)
        probe.unlink(missing_ok=True)
