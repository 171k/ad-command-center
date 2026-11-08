"""Known-CVE detection for dependencies and runtimes (deterministic, offline).

This is the FOUNDATION of a dependency/runtime CVE scanner, kept strictly
separate from the code-level CWE findings:

  1. Build a component inventory from manifests/lockfiles already in the
     extracted tree (npm, PyPI, Composer, Go) and from runtime markers
     (Dockerfile `FROM php:X.Y`, a captured `php -v`, etc.).
  2. Match each component's installed version against an advisory store using
     per-ecosystem version ranges, and report CVE id, component, installed
     version, affected/fixed evidence, source, severity, confidence and
     remediation.

Design constraints honoured:
  * No network in the scan path. Advisories are loaded from a vendored seed and,
    when present, from a bounded importer directory (ADCC_ADVISORY_DIR) — a
    separate process populates it; the scan only reads it.
  * We never claim an exploit occurred because a vulnerable version is present.
  * When a component's version is unknown, status is reported as undetermined,
    never as vulnerable or safe.

The vendored seed is intentionally tiny and labelled as examples; a complete
offline database (e.g. an OSV/Trivy export) is the deferred importer step.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

# ---------------------------------------------------------------- version model

_NUM = re.compile(r"\d+")


def _parse_version(v: str) -> tuple[int, ...]:
    """Loose numeric version tuple. Pre-release/build metadata is dropped, so
    comparisons are approximate across ecosystems (documented limitation)."""
    core = (v or "").strip().lstrip("vV=^~> ").split("+")[0].split("-")[0]
    parts = _NUM.findall(core)
    return tuple(int(p) for p in parts[:4]) or (0,)


def _cmp(a: str, b: str) -> int:
    ta, tb = _parse_version(a), _parse_version(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def version_in_range(version: str, introduced: str | None, fixed: str | None) -> bool:
    """True if `introduced <= version < fixed` (either bound optional)."""
    if not version:
        return False
    if introduced and _cmp(version, introduced) < 0:
        return False
    if fixed and _cmp(version, fixed) >= 0:
        return False
    return True


# ------------------------------------------------------------- advisory store

_SEED: list[dict] = [
    # Clearly-labelled EXAMPLE advisories for well-known, long-stable CVEs so the
    # matcher is useful out of the box. This is NOT a complete database.
    {
        "id": "CVE-2021-23337", "ecosystem": "npm", "package": "lodash",
        "ranges": [{"introduced": "0", "fixed": "4.17.21"}],
        "severity": "high", "summary": "Command injection via template in lodash.",
        "fixed_version": "4.17.21", "source": "seed",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"],
    },
    {
        "id": "CVE-2021-44906", "ecosystem": "npm", "package": "minimist",
        "ranges": [{"introduced": "0", "fixed": "1.2.6"}],
        "severity": "critical", "summary": "Prototype pollution in minimist.",
        "fixed_version": "1.2.6", "source": "seed",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44906"],
    },
    {
        "id": "CVE-2022-40897", "ecosystem": "PyPI", "package": "setuptools",
        "ranges": [{"introduced": "0", "fixed": "65.5.1"}],
        "severity": "high", "summary": "ReDoS in setuptools package_index.",
        "fixed_version": "65.5.1", "source": "seed",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-40897"],
    },
]


def load_advisories() -> list[dict]:
    """Seed advisories plus any vendored/imported ones under ADCC_ADVISORY_DIR.

    The importer directory is populated out-of-band (never during a scan). Each
    file is a JSON list of advisory objects in the same shape as the seed.
    """
    advisories = list(_SEED)
    d = os.environ.get("ADCC_ADVISORY_DIR")
    if d and Path(d).is_dir():
        for p in sorted(Path(d).glob("*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    advisories.extend(x for x in data if isinstance(x, dict))
            except (OSError, json.JSONDecodeError):
                continue
    return advisories


# --------------------------------------------------------------- inventory

def _norm(name: str) -> str:
    return (name or "").strip().lower().replace("_", "-")


def parse_requirements(text: str, source: str) -> list[dict]:
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._!+-]+)", line)
        if m:
            out.append({"ecosystem": "PyPI", "name": _norm(m.group(1)),
                        "version": m.group(2), "source": source, "kind": "dependency"})
        elif re.match(r"^[A-Za-z0-9._-]+$", line):
            out.append({"ecosystem": "PyPI", "name": _norm(line), "version": "",
                        "source": source, "kind": "dependency"})
    return out


def parse_package_lock(text: str, source: str) -> list[dict]:
    out = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return out
    # npm lockfile v2/v3: "packages" map keyed by node_modules/<name>.
    for key, meta in (data.get("packages") or {}).items():
        if not key or not isinstance(meta, dict):
            continue
        name = key.split("node_modules/")[-1]
        ver = meta.get("version", "")
        if name and ver:
            out.append({"ecosystem": "npm", "name": _norm(name), "version": ver,
                        "source": source, "kind": "dependency"})
    # legacy v1: "dependencies" tree.
    def _walk(deps):
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict):
                if meta.get("version"):
                    out.append({"ecosystem": "npm", "name": _norm(name),
                                "version": meta["version"], "source": source,
                                "kind": "dependency"})
                _walk(meta.get("dependencies"))
    if not data.get("packages"):
        _walk(data.get("dependencies"))
    return out


def parse_composer_lock(text: str, source: str) -> list[dict]:
    out = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return out
    for pkg in (data.get("packages") or []) + (data.get("packages-dev") or []):
        if isinstance(pkg, dict) and pkg.get("name"):
            out.append({"ecosystem": "Packagist", "name": _norm(pkg["name"]),
                        "version": str(pkg.get("version", "")), "source": source,
                        "kind": "dependency"})
    return out


def parse_go_mod(text: str, source: str) -> list[dict]:
    out = []
    for m in re.finditer(r"^\s*([\w./-]+)\s+v([\w.\-+]+)", text, re.MULTILINE):
        name = m.group(1)
        if name in ("module", "go", "require", "toolchain"):
            continue
        out.append({"ecosystem": "Go", "name": _norm(name),
                    "version": m.group(2), "source": source, "kind": "dependency"})
    return out


def parse_dockerfile_runtime(text: str, source: str) -> list[dict]:
    """Runtime inventory from `FROM <image>:<tag>` lines (php, node, python...)."""
    out = []
    for m in re.finditer(r"^\s*FROM\s+([\w./-]+):([\w.\-]+)", text, re.MULTILINE | re.IGNORECASE):
        image, tag = m.group(1).split("/")[-1].lower(), m.group(2)
        if _NUM.search(tag):
            out.append({"ecosystem": "runtime", "name": image,
                        "version": tag, "source": source, "kind": "runtime"})
    return out


_PARSERS = [
    (re.compile(r"(^|/)package-lock\.json$|(^|/)npm-shrinkwrap\.json$"), parse_package_lock),
    (re.compile(r"(^|/)requirements[\w.-]*\.txt$"), parse_requirements),
    (re.compile(r"(^|/)composer\.lock$"), parse_composer_lock),
    (re.compile(r"(^|/)go\.mod$"), parse_go_mod),
    (re.compile(r"(^|/)Dockerfile[\w.-]*$|(^|/)[\w.-]*\.dockerfile$"), parse_dockerfile_runtime),
]


def build_inventory(workdir: Path, rel_paths: list[str]) -> list[dict]:
    """Parse every recognised manifest/lockfile/runtime marker in the tree."""
    inv: list[dict] = []
    seen: set = set()
    for rel in rel_paths:
        for rx, parser in _PARSERS:
            if rx.search(rel):
                try:
                    text = (workdir / rel).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    break
                for c in parser(text, rel):
                    key = (c["ecosystem"], c["name"], c["version"], c["source"])
                    if key not in seen:
                        seen.add(key)
                        inv.append(c)
                break
    return inv


# --------------------------------------------------------------- matching

def match_component(comp: dict, advisories: list[dict]) -> list[dict]:
    findings = []
    for adv in advisories:
        if adv.get("ecosystem") != comp["ecosystem"]:
            continue
        if _norm(adv.get("package", "")) != comp["name"]:
            continue
        if not comp["version"]:
            findings.append(_finding(comp, adv, matched=None,
                                     note="Installed version unknown; cannot confirm."))
            continue
        matched = any(version_in_range(comp["version"], r.get("introduced"), r.get("fixed"))
                      for r in adv.get("ranges", [{}]))
        if matched:
            findings.append(_finding(comp, adv, matched=True))
    return findings


def _finding(comp: dict, adv: dict, matched: bool | None, note: str = "") -> dict:
    fixed = adv.get("fixed_version") or next(
        (r.get("fixed") for r in adv.get("ranges", []) if r.get("fixed")), None)
    if matched is None:
        confidence = "undetermined"
    elif comp["kind"] == "runtime":
        # Distro backports can patch a CVE without changing the upstream version.
        confidence = "potential (verify vendor backport)"
    else:
        confidence = "strong (exact version match)"
    remediation = (f"Upgrade {comp['name']} to {fixed} or later."
                   if fixed else f"Update {comp['name']} to a fixed release.")
    return {
        "cve": adv["id"], "component": comp["name"], "ecosystem": comp["ecosystem"],
        "installed_version": comp["version"] or "unknown",
        "fixed_version": fixed, "severity": adv.get("severity", "unknown"),
        "summary": adv.get("summary", ""), "source": adv.get("source", ""),
        "references": adv.get("references", []),
        "confidence": confidence, "kind": comp["kind"],
        "source_file": comp["source"], "remediation": remediation,
        "note": note,
    }


def scan_tree_for_cves(workdir: Path, rel_paths: list[str]) -> dict:
    """Inventory + advisory match for an extracted tree. Never executes code."""
    advisories = load_advisories()
    inventory = build_inventory(workdir, rel_paths)
    findings: list[dict] = []
    for comp in inventory:
        findings.extend(match_component(comp, advisories))
    sev_order = {"critical": 3, "high": 2, "medium": 1, "low": 0, "unknown": 0}
    findings.sort(key=lambda f: (-sev_order.get(f["severity"], 0), f["component"]))
    ecosystems = sorted({c["ecosystem"] for c in inventory})
    runtimes = [c for c in inventory if c["kind"] == "runtime"]
    limitations = [
        "Advisory data is a small vendored seed plus any imported DB; it is not a "
        "complete CVE database. Load a full offline DB via ADCC_ADVISORY_DIR.",
        "Version comparison is numeric and ignores pre-release/epoch; edge cases "
        "may be imprecise.",
        "A vulnerable version being present does NOT prove exploitation.",
    ]
    if not runtimes:
        limitations.append(
            "No runtime/container inventory supplied, so runtime (e.g. PHP) CVE "
            "status cannot be determined from application source alone.")
    return {
        "inventory_count": len(inventory),
        "ecosystems": ecosystems,
        "findings": findings,
        "advisory_count": len(advisories),
        "limitations": limitations,
    }
