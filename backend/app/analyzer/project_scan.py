"""Whole-project scan: a service zip is extracted to a sandbox temp dir, statically
analyzed (built-in rules + Semgrep) and deleted. The source is NEVER executed.

Safety: the archive is untrusted, so extraction guards against zip-slip (path
traversal), zip bombs (file count and total-size caps), symlinks and oversized
members. Results are aggregated per file and stored on the scan job.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from .. import db
from . import correlate, cve, engine
from .enrich import cwe_number, enrich_for_cwe

# Bounds (generous: this runs during prep, not in the request path).
MAX_FILES = 5000
MAX_TOTAL_UNCOMPRESSED = 300 * 1024 * 1024   # 300 MB
MAX_MEMBER_BYTES = 2 * 1024 * 1024           # 2 MB per source file
MAX_RATIO = 200                              # per-member compression ratio guard
SEMGREP_PROC_TIMEOUT = 600                   # seconds for the whole-tree Semgrep run

SKIP_DIRS = {
    "node_modules", "vendor", ".git", ".svn", ".hg", "dist", "build", "__pycache__",
    ".venv", "venv", "env", "site-packages", ".next", ".cache", "bower_components",
    "target", ".idea", ".vscode",
}

EXT_LANG = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".php": "php", ".phtml": "php",
    ".java": "java", ".go": "go", ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp",
    ".hpp": "cpp", ".rb": "ruby", ".sh": "shell", ".bash": "shell",
}

_SEV_CONF = {"ERROR": "strong", "WARNING": "potential", "INFO": "needs_context"}


class ScanError(Exception):
    pass


def _is_skipped(rel: Path) -> bool:
    return any(part in SKIP_DIRS for part in rel.parts)


def extract_zip(zip_path: Path, dest: Path) -> dict:
    """Safely extract a zip into dest. Returns stats and the list of source files."""
    source_files: list[str] = []
    total = 0
    count = 0
    skipped_binary = 0
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as e:
        raise ScanError("Not a valid zip archive.") from e
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename
            # zip-slip / absolute path guard
            if name.startswith("/") or ".." in Path(name).parts or ":" in name[:3]:
                continue
            rel = Path(name)
            if _is_skipped(rel):
                continue
            # symlink guard (unix external attr high bits encode the mode)
            mode = info.external_attr >> 16
            if mode and (mode & 0o170000) == 0o120000:
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                continue
            if info.compress_size > 0 and info.file_size / info.compress_size > MAX_RATIO \
                    and info.file_size > 1_000_000:
                continue
            count += 1
            total += info.file_size
            if count > MAX_FILES:
                raise ScanError(f"Archive has too many files (limit {MAX_FILES}).")
            if total > MAX_TOTAL_UNCOMPRESSED:
                raise ScanError("Archive is too large uncompressed (limit 300 MB).")

            target = (dest / rel).resolve()
            if not str(target).startswith(str(dest.resolve())):
                continue  # final belt-and-suspenders path check
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out, length=65536)

            if rel.suffix.lower() in EXT_LANG:
                # treat as source only if it looks like text (no NUL in the head)
                with open(target, "rb") as fh:
                    head = fh.read(8192)
                if b"\x00" in head:
                    skipped_binary += 1
                    continue
                source_files.append(str(rel).replace("\\", "/"))

    return {"source_files": source_files, "file_count": count,
            "total_bytes": total, "skipped_binary": skipped_binary}


def _semgrep_configs() -> list[str]:
    """Bundled rules, plus the vendored community ruleset when present (project scan)."""
    cfgs = [str(Path(__file__).resolve().parent / "semgrep_rules")]
    community = os.environ.get("ADCC_SEMGREP_COMMUNITY_DIR")
    if community and Path(community).is_dir():
        cfgs.append(community)
    return cfgs


def _run_semgrep_cmd(root: Path, configs: list[str]) -> tuple[int, str]:
    cmd = ["semgrep", "--json", "--quiet", "--metrics=off", "--no-git-ignore",
           "--timeout", "10", "--timeout-threshold", "3",
           "--max-target-bytes", "1500000", "--jobs", "2"]
    for cfg in configs:
        cmd += ["--config", cfg]
    for d in SKIP_DIRS:
        cmd += ["--exclude", d]
    cmd.append(str(root))
    env = {**os.environ, "SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"}
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=SEMGREP_PROC_TIMEOUT, env=env)
    return proc.returncode, proc.stdout


def _semgrep_dir(root: Path) -> dict[str, list[dict]]:
    """Run Semgrep once over the whole tree. Returns {relpath: [finding, ...]}.

    Uses the bundled rules plus the vendored community ruleset. If the combined
    run fails, retries with the bundled rules only so a scan never comes back
    empty just because a community rule misbehaved.
    """
    if not shutil.which("semgrep"):
        return {}
    configs = _semgrep_configs()
    try:
        rc, stdout = _run_semgrep_cmd(root, configs)
        if rc not in (0, 1) and len(configs) > 1:
            rc, stdout = _run_semgrep_cmd(root, configs[:1])  # fall back to bundled only
    except (subprocess.TimeoutExpired, OSError):
        return {}
    if rc not in (0, 1):
        return {}
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return {}
    out: dict[str, list[dict]] = {}
    src_cache: dict[str, list[str]] = {}
    seen: set = set()  # (rel, line, cwe# or rule_id) -> collapse duplicate rules
    for r in data.get("results", []):
        path = r.get("path", "")
        rel = os.path.relpath(path, str(root)).replace("\\", "/")
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        cwe_list = meta.get("cwe", []) or []
        cwe_raw = cwe_list[0] if cwe_list else ""
        enr = enrich_for_cwe(cwe_raw) or {}
        num = cwe_number(cwe_raw)
        cwe = f"CWE-{num}" if num else cwe_raw  # short form for the badge
        conf = _SEV_CONF.get((extra.get("severity") or "WARNING").upper(), "potential")
        start = r.get("start", {})
        end = r.get("end", {})
        line = start.get("line", 0)
        end_line = end.get("line", line)
        check_id = str(r.get("check_id", "semgrep"))
        rule_id = check_id.split(".")[-1]
        # Collapse duplicate rules firing on the same line for the same CWE
        # (our rule + several community rules often overlap).
        key = (rel, line, cwe_number(cwe) or rule_id)
        if key in seen:
            continue
        seen.add(key)
        # Slice evidence from the real extracted source, never from extra.lines
        # (Semgrep can return the "requires login" placeholder there).
        if rel not in src_cache:
            try:
                src_cache[rel] = Path(path).read_text(
                    encoding="utf-8", errors="replace").split("\n")
            except OSError:
                src_cache[rel] = []
        snippet, snip_err = engine.snippet_from_source(src_cache[rel], line, end_line)
        raw = (extra.get("lines", "") or "").strip("\n")
        matched = "" if raw == engine.SEMGREP_PLACEHOLDER else raw
        owasp = meta.get("owasp", []) or []
        msg = extra.get("message", "Semgrep finding")
        out.setdefault(rel, []).append({
            "rule_id": rule_id,
            "rule_source": check_id,
            "name": msg[:140],
            "cwe": cwe,
            "line": line,
            "end_line": end_line,
            "start_col": start.get("col"),
            "end_col": end.get("col"),
            "matched_text": (matched or "\n".join(s["text"] for s in snippet if s["hit"]))[:300],
            "confidence": conf,
            "confidence_label": engine.CONF_LABEL[conf],
            "snippet": snippet,
            "snippet_error": snip_err,
            "description": msg,
            "why_dangerous": enr.get("exploit", "") or meta.get("exploit", ""),
            "preconditions": "", "taint_evidence": None, "test_procedure": "",
            "exploit_template": enr.get("payload", "") or meta.get("payload", ""),
            "remediation": enr.get("patch", "") or meta.get("patch", "") or (extra.get("fix", "") or ""),
            "why_patch_works": "", "regression_test": "",
            "references": meta.get("references", []) or [],
            "limitations": ("Reported by Semgrep (" + ", ".join(owasp) + ").")
            if owasp else "Reported by Semgrep.",
            "engine": "semgrep",
        })
    return out


def _set(job_id: int, **cols) -> None:
    cols["updated_at"] = __import__("datetime").datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    keys = ", ".join(f"{k}=?" for k in cols)
    db.execute(f"UPDATE scan_jobs SET {keys} WHERE id=?", (*cols.values(), job_id))


def analyze_tree(workdir: Path, files: list[str], progress=None) -> dict:
    """Scan an already-extracted source tree and return the result dict.

    Pure (no DB): built-in rules + one whole-tree Semgrep run, merged per file,
    enriched, aggregated, then correlated. `progress(i)` is an optional callback
    for scanned-file counts. The source is read, never executed.
    """
    sg_by_file = _semgrep_dir(workdir)

    per_file: dict[str, list[dict]] = {}
    for i, rel in enumerate(files):
        lang = EXT_LANG.get(Path(rel).suffix.lower())
        try:
            code = (workdir / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        builtin = engine.analyze(code, lang, use_semgrep=False)["findings"]
        merged = list(builtin)
        seen = {(f["line"], cwe_number(f.get("cwe"))) for f in builtin}
        for sg in sg_by_file.get(rel, []):
            if (sg["line"], cwe_number(sg.get("cwe"))) not in seen:
                merged.append(sg)
        if merged:
            merged.sort(key=lambda f: (-engine.CONF_ORDER.get(f["confidence"], 0), f["line"]))
            per_file[rel] = merged
        if progress and i % 25 == 0:
            progress(i + 1)

    # Semgrep may flag files the built-in loop skipped (other languages).
    for rel, sgs in sg_by_file.items():
        if rel not in per_file and sgs:
            sgs.sort(key=lambda f: (-engine.CONF_ORDER.get(f["confidence"], 0), f["line"]))
            per_file[rel] = sgs

    for findings in per_file.values():
        for f in findings:
            engine._add_display_fields(f)

    file_entries = []
    totals = {"strong": 0, "potential": 0, "needs_context": 0}
    for rel, findings in per_file.items():
        counts = {"strong": 0, "potential": 0, "needs_context": 0}
        for f in findings:
            counts[f["confidence"]] = counts.get(f["confidence"], 0) + 1
            totals[f["confidence"]] = totals.get(f["confidence"], 0) + 1
        file_entries.append({"path": rel, "findings": findings, "counts": counts})
    # Worst files first: strong, then potential, then total.
    file_entries.sort(key=lambda e: (-e["counts"]["strong"], -e["counts"]["potential"],
                                     -len(e["findings"]), e["path"]))

    # Evidence-based correlation across files (shared symbols + imports).
    sources: dict[str, str] = {}
    for e in file_entries:
        try:
            sources[e["path"]] = (workdir / e["path"]).read_text(
                encoding="utf-8", errors="replace")
        except OSError:
            sources[e["path"]] = ""
    try:
        related = correlate.build_related(file_entries, sources)
    except Exception:  # noqa: BLE001 - correlation must never fail a scan
        related = []

    # Known-CVE scan of dependency manifests / runtime markers (distinct from the
    # code-level CWE findings above). Walk the extracted tree for manifests.
    try:
        all_rels = [str(p.relative_to(workdir)).replace("\\", "/")
                    for p in workdir.rglob("*") if p.is_file()]
        cve_report = cve.scan_tree_for_cves(workdir, all_rels)
    except Exception:  # noqa: BLE001 - CVE scan must never fail the code scan
        cve_report = {"inventory_count": 0, "findings": [], "ecosystems": [],
                      "advisory_count": 0, "limitations": ["CVE scan unavailable."]}

    return {
        "files": file_entries,
        "related": related,
        "cve": cve_report,
        "totals": totals,
        "files_with_findings": len(file_entries),
        "files_scanned": len(files),
        "finding_count": sum(len(e["findings"]) for e in file_entries),
        "semgrep_ran": bool(shutil.which("semgrep")),
        "community_rules": len(_semgrep_configs()) > 1,
        "disclaimer": "Deterministic static analysis of extracted source. The code is "
                      "never executed. Findings are patterns, not proven exploitability.",
    }


def scan_project(job_id: int, zip_path: str) -> None:
    """Background worker: extract, scan built-in + Semgrep, aggregate, store, clean up."""
    zp = Path(zip_path)
    workdir = Path(tempfile.mkdtemp(prefix="adcc_scan_"))
    try:
        _set(job_id, status="running", phase="Extracting archive")
        stats = extract_zip(zp, workdir)
        files = stats["source_files"]
        _set(job_id, total_files=len(files), phase="Running Semgrep over the project")

        result = analyze_tree(workdir, files, progress=lambda n: _set(job_id, scanned_files=n))
        result["archive_files"] = stats["file_count"]
        result["skipped_binary"] = stats["skipped_binary"]

        _set(job_id, status="done", phase="Done", scanned_files=len(files),
             finding_count=result["finding_count"], result=json.dumps(result))
    except ScanError as e:
        _set(job_id, status="error", phase="Failed", error=str(e))
    except Exception as e:  # noqa: BLE001 - record any worker failure on the job
        _set(job_id, status="error", phase="Failed", error=f"{type(e).__name__}: {e}"[:300])
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
        try:
            zp.unlink(missing_ok=True)
        except OSError:
            pass
