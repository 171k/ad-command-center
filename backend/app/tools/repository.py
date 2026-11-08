"""Server-hosted tool repository: safe artifact storage, SHA-256 integrity,
and offline-bundle export.

Design:
  - Artifact bytes are stored on the filesystem under tools_dir/<slug>/, never as
    DB blobs. The DB holds metadata + the SHA-256 for verification.
  - Filenames are sanitized; stored paths are validated to stay within tools_dir
    (no path traversal). Downloads stream from disk with the checksum in a header.
  - The offline bundle is a single .zip containing every hosted artifact, a
    manifest (catalog + checksums), the `adtools` CLI, and a README — so the team
    can install everything with no network / no GitHub.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from pathlib import Path

from .. import db
from ..config import get_settings

_SAFE = re.compile(r"[^A-Za-z0-9._+-]")


def safe_name(name: str) -> str:
    name = _SAFE.sub("_", (name or "").strip()).strip("._")
    return name[:128] or "artifact"


def _tool_dir(slug: str) -> Path:
    s = get_settings()
    d = (s.tools_dir / safe_name(slug)).resolve()
    if s.tools_dir.resolve() not in d.parents and d != s.tools_dir.resolve():
        raise ValueError("unsafe tool path")
    d.mkdir(parents=True, exist_ok=True)
    return d


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def save_artifact(slug: str, filename: str, data: bytes) -> dict:
    s = get_settings()
    if len(data) > s.max_tool_artifact_bytes:
        raise ValueError(f"artifact exceeds {s.max_tool_artifact_bytes} bytes")
    fn = safe_name(filename)
    d = _tool_dir(slug)
    path = (d / fn).resolve()
    if d not in path.parents:
        raise ValueError("unsafe filename")
    digest = sha256_bytes(data)
    path.write_bytes(data)
    rel = str(path.relative_to(s.tools_dir))
    return {"filename": fn, "sha256": digest, "size_bytes": len(data), "storage_path": rel}


def artifact_abspath(storage_path: str) -> Path:
    s = get_settings()
    p = (s.tools_dir / storage_path).resolve()
    if s.tools_dir.resolve() not in p.parents:
        raise ValueError("unsafe storage path")
    return p


def verify_artifact(row: dict) -> dict:
    try:
        p = artifact_abspath(row["storage_path"])
    except ValueError:
        return {"ok": False, "reason": "unsafe path"}
    if not p.exists():
        return {"ok": False, "reason": "file missing"}
    actual = sha256_file(p)
    return {"ok": actual == row["sha256"], "expected": row["sha256"], "actual": actual}


# ---------------- catalog helpers ----------------

def _loads(v, default):
    if not v:
        return default
    try:
        return json.loads(v)
    except Exception:
        return default


def tool_to_dict(row: dict, with_artifacts: bool = False) -> dict:
    d = dict(row)
    for k, dflt in (("os_support", []), ("dependencies", []), ("install", {}), ("tags", [])):
        d[k] = _loads(d.get(k), dflt)
    if with_artifacts:
        arts = db.query("SELECT id, filename, os, arch, size_bytes, sha256, storage_path, notes, created_at "
                        "FROM tool_artifacts WHERE tool_id=? ORDER BY id", (row["id"],))
        d["artifacts"] = [dict(a) for a in arts]
    return d


def manifest() -> dict:
    """Full catalog + artifacts + checksums (the offline-install source of truth)."""
    tools = []
    for t in db.query("SELECT * FROM tools ORDER BY category, name"):
        tools.append(tool_to_dict(dict(t), with_artifacts=True))
    return {"generated_at": _now(), "tool_count": len(tools), "tools": tools}


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def build_offline_bundle(adtools_source: str, readme: str) -> bytes:
    """Return a .zip with manifest, all artifacts, the adtools CLI, and a README."""
    man = manifest()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(man, indent=2))
        z.writestr("adtools.py", adtools_source)
        z.writestr("README.md", readme)
        for t in man["tools"]:
            for a in t.get("artifacts", []):
                row = db.query_one("SELECT storage_path FROM tool_artifacts WHERE id=?", (a["id"],))
                if not row:
                    continue
                try:
                    p = artifact_abspath(row["storage_path"])
                except ValueError:
                    continue
                if p.exists():
                    z.write(p, f"artifacts/{row['storage_path']}")
    return buf.getvalue()
