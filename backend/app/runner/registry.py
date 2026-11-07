"""The runner ALLOWLIST. Only tasks defined here can ever execute.

Each task is a fixed local utility: a specific bundled script run by the Python
interpreter with a strict parameter schema. There is no way to run an arbitrary
command, binary, path, or shell string through this registry — args are validated
and passed to the child as JSON on stdin (never interpolated into a command line).
All tasks are offline, deterministic, and non-target-facing.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

TASKS_DIR = Path(__file__).resolve().parent / "tasks"


@dataclass
class Param:
    name: str
    type: str            # "str" | "int" | "bool" | "enum"
    required: bool = False
    max_len: int = 4096
    choices: tuple = ()
    default: object = None


@dataclass
class Task:
    id: str
    title: str
    description: str
    script: str                      # filename under tasks/ (allowlisted)
    params: list[Param]
    timeout_s: int = 5
    cpu_s: int = 4                   # RLIMIT_CPU (POSIX)
    mem_mb: int = 256               # RLIMIT_AS (POSIX)
    max_output_bytes: int = 256_000

    def script_path(self) -> Path:
        p = (TASKS_DIR / self.script).resolve()
        # defense in depth: the resolved path must stay inside TASKS_DIR
        if TASKS_DIR not in p.parents:
            raise ValueError("task script escapes tasks dir")
        return p


TASKS: list[Task] = [
    Task(
        id="hash_identify",
        title="Identify hash type",
        description="Heuristically identify likely hash algorithms from a string.",
        script="hash_identify.py",
        params=[Param("value", "str", required=True, max_len=512)],
        timeout_s=3, cpu_s=2,
    ),
    Task(
        id="hash_crack",
        title="Dictionary-check a weak hash",
        description="Check an unsalted MD5/SHA1/SHA256 against a small bundled wordlist (offline).",
        script="hash_crack.py",
        params=[
            Param("hash", "str", required=True, max_len=128),
            Param("algo", "enum", choices=("md5", "sha1", "sha256"), default="md5"),
        ],
        timeout_s=5, cpu_s=4,
    ),
    Task(
        id="wordlist_mutate",
        title="Generate password mutations",
        description="Produce common mutations (case, leet, year/suffix) from a base word.",
        script="wordlist_mutate.py",
        params=[
            Param("word", "str", required=True, max_len=32),
            Param("years", "bool", default=True),
        ],
        timeout_s=4, cpu_s=3,
    ),
    Task(
        id="entropy",
        title="Entropy analysis",
        description="Shannon entropy + printable ratio to spot encoding/encryption.",
        script="entropy.py",
        params=[Param("text", "str", required=True, max_len=100_000)],
        timeout_s=4, cpu_s=3,
    ),
]

BY_ID = {t.id: t for t in TASKS}


class ValidationError(Exception):
    pass


def validate_args(task: Task, raw: dict) -> dict:
    """Strictly validate and coerce args against the task's schema."""
    if not isinstance(raw, dict):
        raise ValidationError("args must be an object")
    out: dict = {}
    allowed = {p.name for p in task.params}
    extra = set(raw) - allowed
    if extra:
        raise ValidationError(f"unexpected args: {sorted(extra)}")
    for p in task.params:
        if p.name not in raw or raw[p.name] is None:
            if p.required:
                raise ValidationError(f"missing required arg: {p.name}")
            out[p.name] = p.default
            continue
        v = raw[p.name]
        if p.type == "str":
            if not isinstance(v, str):
                raise ValidationError(f"{p.name} must be a string")
            if len(v) > p.max_len:
                raise ValidationError(f"{p.name} exceeds {p.max_len} chars")
            out[p.name] = v
        elif p.type == "int":
            if not isinstance(v, int) or isinstance(v, bool):
                raise ValidationError(f"{p.name} must be an integer")
            out[p.name] = v
        elif p.type == "bool":
            if not isinstance(v, bool):
                raise ValidationError(f"{p.name} must be a boolean")
            out[p.name] = v
        elif p.type == "enum":
            if v not in p.choices:
                raise ValidationError(f"{p.name} must be one of {list(p.choices)}")
            out[p.name] = v
    return out


def task_summaries() -> list[dict]:
    return [
        {
            "id": t.id, "title": t.title, "description": t.description,
            "timeout_s": t.timeout_s,
            "params": [
                {"name": p.name, "type": p.type, "required": p.required,
                 "choices": list(p.choices), "default": p.default, "max_len": p.max_len}
                for p in t.params
            ],
        }
        for t in TASKS
    ]
