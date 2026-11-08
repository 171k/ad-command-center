"""Evidence-based finding correlation (deterministic, no AI).

Links findings into "related" groups ONLY when there is concrete, inspectable
evidence connecting them:

  * a shared security-relevant identifier that appears in both findings'
    evidence (e.g. the same signing-secret constant), or
  * a source import edge between the two files (A imports B).

It never asserts a fixed exploit chain and never claims exploitability: source
findings are weaknesses, not proven exploits. Each group records the exact
evidence used so an analyst can verify it. If nothing connects two findings,
they stay separate.
"""
from __future__ import annotations

import os
import re

from .enrich import cwe_number

# Identifiers worth linking on: long enough to be meaningful, and security-ish.
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,}")
_SECURITY_HINT = re.compile(
    r"secret|key|token|sign|hmac|hash|digest|auth|role|admin|cred|pass|session|priv|jwt|flag",
    re.I,
)
# Imports: `import x from "y"`, `import {..} from "y"`, `require("y")`.
_IMPORT = re.compile(
    r"""(?:from|require)\s*\(?\s*['"]([^'"]+)['"]""",
)

# Common words that are not useful link evidence even if they are long.
_STOP = {
    "const", "function", "return", "require", "module", "exports", "default",
    "import", "export", "true", "false", "null", "undefined", "await", "async",
    "string", "number", "object", "value", "error", "status", "length", "console",
}

# CWE buckets for a conservative chain label.
_INTEGRITY = {"200", "201", "208", "312", "319", "321", "347", "522", "798"}
_ACCESS = {"22", "23", "73", "98", "284", "285", "862", "863", "639", "1286"}


def _security_symbols(text: str) -> set[str]:
    out = set()
    for w in _IDENT.findall(text or ""):
        if w.lower() in _STOP:
            continue
        if _SECURITY_HINT.search(w):
            out.add(w)
    return out


def _finding_evidence_text(f: dict) -> str:
    parts = [f.get("matched_text", "")]
    parts += [s.get("text", "") for s in (f.get("snippet") or []) if s.get("hit")]
    return "\n".join(parts)


def _resolve_import(src_rel: str, spec: str, known: set[str]) -> str | None:
    """Resolve a relative import spec to a known project file, else None."""
    if not spec.startswith("."):
        return None  # bare package import, not a local file
    base = os.path.dirname(src_rel)
    target = os.path.normpath(os.path.join(base, spec)).replace("\\", "/")
    cands = [target]
    for ext in (".js", ".jsx", ".ts", ".tsx", ".mjs"):
        cands.append(target + ext)
        cands.append(f"{target}/index{ext}")
    for c in cands:
        if c in known:
            return c
    return None


def _import_edges(sources: dict[str, str]) -> set[tuple[str, str]]:
    known = set(sources)
    edges: set[tuple[str, str]] = set()
    for rel, code in sources.items():
        for spec in _IMPORT.findall(code or ""):
            tgt = _resolve_import(rel, spec, known)
            if tgt and tgt != rel:
                edges.add((rel, tgt))
    return edges


def _label(cwes: set[str], has_import: bool, has_symbol: bool) -> str:
    integ = cwes & _INTEGRITY
    acc = cwes & _ACCESS
    if integ and acc:
        return ("An authentication/secret weakness and an access-control weakness "
                "appear together and share evidence, so compromising the first may "
                "enable the second. Verify by testing in an authorized lab.")
    if has_symbol:
        return "These findings reference the same security-relevant symbol."
    if has_import:
        return "These findings are in modules connected by a source import."
    return "Related findings."


class _DSU:
    def __init__(self, n: int):
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def build_related(file_entries: list[dict], sources: dict[str, str]) -> list[dict]:
    """Return evidence-linked groups of findings across the project.

    file_entries: [{"path", "findings": [...]}]; sources: {rel: code}.
    Only groups with >=2 findings and concrete evidence are returned.
    """
    # Flatten findings with an index.
    flat: list[dict] = []
    for fe in file_entries:
        for f in fe["findings"]:
            flat.append({
                "path": fe["path"], "line": f.get("line"),
                "cwe": f.get("cwe"), "cwe_num": cwe_number(f.get("cwe")),
                "vuln_name": f.get("vuln_name") or f.get("name"),
                "confidence": f.get("confidence"),
                "symbols": _security_symbols(_finding_evidence_text(f)),
            })
    n = len(flat)
    if n < 2:
        return []

    edges = _import_edges(sources)
    dsu = _DSU(n)
    # evidence collected per union so we can explain each group.
    pair_symbol: dict[tuple[int, int], set[str]] = {}
    import_pairs: set[tuple[int, int]] = set()

    for i in range(n):
        for j in range(i + 1, n):
            a, b = flat[i], flat[j]
            if a["path"] == b["path"]:
                continue  # same-file lines are shown together already
            shared = a["symbols"] & b["symbols"]
            linked_import = (a["path"], b["path"]) in edges or (b["path"], a["path"]) in edges
            if shared or linked_import:
                dsu.union(i, j)
                if shared:
                    pair_symbol[(i, j)] = shared
                if linked_import:
                    import_pairs.add((i, j))

    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(dsu.find(i), []).append(i)

    out: list[dict] = []
    gid = 0
    for members in groups.values():
        if len(members) < 2:
            continue
        mset = set(members)
        symbols: set[str] = set()
        has_import = False
        for (i, j), syms in pair_symbol.items():
            if i in mset and j in mset:
                symbols |= syms
        for (i, j) in import_pairs:
            if i in mset and j in mset:
                has_import = True
        cwes = {flat[m]["cwe_num"] for m in members if flat[m]["cwe_num"]}
        evidence = []
        if symbols:
            evidence.append("shared symbol: " + ", ".join(sorted(symbols)[:5]))
        if has_import:
            paths = sorted({flat[m]["path"] for m in members})
            evidence.append("connected by source imports (" + ", ".join(paths[:4]) + ")")
        gid += 1
        out.append({
            "id": gid,
            "label": _label(cwes, has_import, bool(symbols)),
            "evidence": evidence,
            "members": [
                {"path": flat[m]["path"], "line": flat[m]["line"],
                 "cwe": flat[m]["cwe"], "vuln_name": flat[m]["vuln_name"],
                 "confidence": flat[m]["confidence"]}
                for m in sorted(members, key=lambda m: (flat[m]["path"], flat[m]["line"] or 0))
            ],
            "note": "Correlation from static evidence only. It suggests findings may "
                    "combine; it does not prove an exploit chain.",
        })
    out.sort(key=lambda g: (-len(g["members"]), g["id"]))
    return out
