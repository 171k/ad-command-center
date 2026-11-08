"""Deterministic analysis engine. No AI, no network, no code execution.

Algorithm:
  1. Pick rules for the (detected or chosen) language.
  2. For each rule, scan the source with its compiled sink regex.
  3. For every match, compute a confidence category:
       - start from the rule's base confidence (potential / needs_context)
       - if a known taint source for the language appears within a small window
         of lines around the sink, upgrade toward "strong"
       - if an obvious safe marker is present, note it (kept as potential)
  4. Emit a structured finding with matched line numbers, a highlighted
     snippet, remediation, regression test, references and limitations.

"No matching rule" is reported as its own category and explicitly does NOT
assert the code is secure.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .enrich import cwe_fix_url, cwe_name, cwe_number, enrich_for_cwe, find_cves
from .rules import LANG_ALIASES, TAINT_SOURCES, Rule, rules_for_language

WINDOW = 3  # lines above/below a sink to look for a taint source

CONF_ORDER = {"needs_context": 0, "potential": 1, "strong": 2}
CONF_LABEL = {
    "strong": "Strongly supported finding",
    "potential": "Potential vulnerability",
    "needs_context": "Requires additional context",
    "none": "No matching rule",
}

# crude but useful language guesser for snippets
_LANG_HINTS = [
    ("php", [r"<\?php", r"\$_(GET|POST|REQUEST)", r"->query\("]),
    ("python", [r"\bdef\s+\w+\s*\(", r"\bimport\s+\w+", r"request\.(args|form)"]),
    ("javascript", [r"\brequire\(", r"=>", r"console\.log", r"req\.(query|body)"]),
    ("java", [r"public\s+class", r"System\.out", r"PreparedStatement"]),
    ("c", [r"#include\s*<", r"\bint\s+main\s*\(", r"printf\("]),
    ("shell", [r"^#!/bin/(ba)?sh", r"\bfi\b", r"\becho\s"]),
]


def detect_language(code: str) -> str:
    scores: dict[str, int] = {}
    for lang, pats in _LANG_HINTS:
        scores[lang] = sum(1 for p in pats if re.search(p, code, re.MULTILINE))
    best = max(scores, key=scores.get) if scores else "python"
    return best if scores.get(best, 0) > 0 else "python"


def _line_of(code: str, pos: int) -> int:
    return code.count("\n", 0, pos) + 1


def _snippet(lines: list[str], line_no: int, span: int = 2) -> list[dict]:
    start = max(1, line_no - span)
    end = min(len(lines), line_no + span)
    return [
        {"n": i, "text": lines[i - 1], "hit": i == line_no}
        for i in range(start, end + 1)
    ]


# Semgrep can withhold the matched source text, returning this literal placeholder
# in `extra.lines` (seen on offline/registry-gated runs). Never display it.
SEMGREP_PLACEHOLDER = "requires login"


def snippet_from_source(
    source_lines: list[str], start_line: int, end_line: int, context: int = 5
) -> tuple[list[dict], str | None]:
    """Slice an evidence snippet straight from the real source.

    Returns (snippet, error). `snippet` is a list of {n, text, hit} where `n` is
    the TRUE 1-based source line number and `hit` marks the matched span
    [start_line, end_line]. We never trust a tool's own `lines` field: we re-read
    the source so line numbers, context and highlighting are always accurate.

    If the reported location cannot be resolved against the source, we return an
    explicit error instead of fabricating a line-1 snippet.
    """
    n = len(source_lines)
    if not source_lines or start_line < 1 or start_line > n:
        return [], f"Source location {start_line} is outside the file (1-{n})."
    end_line = max(start_line, min(end_line or start_line, n))
    lo = max(1, start_line - context)
    hi = min(n, end_line + context)
    snippet = [
        {"n": i, "text": source_lines[i - 1], "hit": start_line <= i <= end_line}
        for i in range(lo, hi + 1)
    ]
    return snippet, None


def _taint_near(code_lines: list[str], line_no: int, sources: list[re.Pattern]) -> str | None:
    lo = max(0, line_no - 1 - WINDOW)
    hi = min(len(code_lines), line_no + WINDOW)
    chunk = "\n".join(code_lines[lo:hi])
    for pat in sources:
        m = pat.search(chunk)
        if m:
            return m.group(0)
    return None


def _match_rule(rule: Rule, code: str, code_lines: list[str], sources: list[re.Pattern]) -> list[dict]:
    flags = re.MULTILINE | re.IGNORECASE | rule.flags
    try:
        pat = re.compile(rule.sink, flags)
    except re.error:
        return []
    findings: list[dict] = []
    seen_lines: set[int] = set()
    for m in pat.finditer(code):
        line_no = _line_of(code, m.start())
        if line_no in seen_lines:
            continue
        seen_lines.add(line_no)

        confidence = rule.base_confidence
        taint = _taint_near(code_lines, line_no, sources)
        if taint:
            confidence = "strong"

        lang = rule.languages[0]
        findings.append(
            {
                "rule_id": rule.id,
                "rule_source": f"builtin:{rule.id}",
                "name": rule.name,
                "cwe": rule.cwe,
                "language": lang,
                "line": line_no,
                "end_line": line_no,
                "matched_text": m.group(0).strip()[:300],
                "confidence": confidence,
                "confidence_label": CONF_LABEL[confidence],
                "snippet": _snippet(code_lines, line_no, span=5),
                "snippet_error": None,
                "description": rule.description,
                "why_dangerous": rule.why,
                "preconditions": rule.preconditions,
                "taint_evidence": taint,
                "test_procedure": rule.test_procedure,
                "exploit_template": rule.exploit_template,
                "remediation": rule.remediation.get(lang) or next(iter(rule.remediation.values()), ""),
                "why_patch_works": rule.why_patch_works,
                "regression_test": rule.regression_test.get(lang) or next(iter(rule.regression_test.values()), ""),
                "references": rule.references,
                "limitations": rule.limitations,
                "engine": "builtin",
            }
        )
    return findings


def _add_display_fields(f: dict) -> None:
    """Human vuln name + a 'how to fix' link (CWE page) + any CVE links."""
    f["vuln_name"] = cwe_name(f.get("cwe")) or f.get("name")
    f["fix_url"] = cwe_fix_url(f.get("cwe"))
    f["cves"] = find_cves(f.get("name", ""), f.get("description", ""), *(f.get("references") or []))


def analyze(code: str, language: str | None = None, use_semgrep: bool = True) -> dict:
    code = code.replace("\r\n", "\n")
    detected = detect_language(code) if not language else LANG_ALIASES.get(language.lower(), language.lower())
    code_lines = code.split("\n")
    source_pats = [re.compile(p) for p in TAINT_SOURCES.get(detected, [])]

    findings: list[dict] = []
    for rule in rules_for_language(detected):
        findings.extend(_match_rule(rule, code, code_lines, source_pats))

    engine_used = "builtin"
    semgrep_note = None
    if use_semgrep and shutil.which("semgrep"):
        sg, note = _run_semgrep(code, detected)
        if sg:
            # Drop Semgrep findings that duplicate a built-in finding at the same
            # line and CWE, so the operator sees one entry per issue.
            seen = {(f["line"], cwe_number(f.get("cwe"))) for f in findings}
            sg = [s for s in sg if (s["line"], cwe_number(s.get("cwe"))) not in seen]
            findings.extend(sg)
            engine_used = "combined"
        semgrep_note = note
    elif use_semgrep:
        semgrep_note = "Semgrep not installed; used built-in rules only."

    findings.sort(key=lambda f: (-CONF_ORDER.get(f["confidence"], 0), f["line"]))
    for f in findings:
        _add_display_fields(f)

    categories = {c: 0 for c in CONF_LABEL}
    for f in findings:
        categories[f["confidence"]] += 1
    if not findings:
        categories["none"] = 1

    return {
        "language": detected,
        "engine": engine_used,
        "semgrep_note": semgrep_note,
        "finding_count": len(findings),
        "category_counts": categories,
        "findings": findings,
        "no_match_notice": (
            "No rule matched. This does NOT prove the code is secure, it only "
            "means none of the curated signatures fired. Review manually and add "
            "context (framework, input sources) for a stronger assessment."
            if not findings else None
        ),
        "disclaimer": (
            "Deterministic static analysis. Findings indicate patterns, not proven "
            "exploitability. Confirm with the listed safe test procedure in an "
            "authorized environment before acting."
        ),
    }


_SEV_CONF = {"ERROR": "strong", "WARNING": "potential", "INFO": "needs_context"}
_SEMGREP_EXT = {"python": ".py", "javascript": ".js", "typescript": ".ts", "php": ".php",
                "java": ".java", "go": ".go", "c": ".c", "cpp": ".cpp", "ruby": ".rb",
                "shell": ".sh"}


def _run_semgrep(code: str, language: str) -> tuple[list[dict], str]:
    """Run local Semgrep with the bundled offline ruleset. Bounded, no network.

    Each Semgrep finding is enriched from the CWE table so it carries the same
    four answers as a built-in finding: what it is, how it is exploited, an
    example payload and how to patch it.
    """
    import json

    ext = _SEMGREP_EXT.get(language, ".txt")
    rules_dir = Path(__file__).resolve().parent / "semgrep_rules"
    if not rules_dir.exists() or not any(rules_dir.glob("*.yml")):
        # Never use --config auto (it fetches from the registry). Offline only.
        return [], "Semgrep installed but no local ruleset bundled; used built-in rules."
    try:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / f"snippet{ext}"
            src.write_text(code, encoding="utf-8")
            cmd = ["semgrep", "--json", "--quiet", "--timeout", "15",
                   "--metrics=off", "--no-git-ignore",
                   "--config", str(rules_dir), str(src)]
            # Force fully offline: no registry version check, no metrics upload.
            env = {**os.environ, "SEMGREP_ENABLE_VERSION_CHECK": "0",
                   "SEMGREP_SEND_METRICS": "off"}
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=40, env=env)
            if proc.returncode not in (0, 1):
                return [], f"Semgrep exited {proc.returncode}: {proc.stderr[:200]}"
            data = json.loads(proc.stdout or "{}")
            src_lines = code.split("\n")
            out = []
            for r in data.get("results", []):
                extra = r.get("extra", {})
                meta = extra.get("metadata", {})
                cwe_list = meta.get("cwe", []) or []
                cwe = cwe_list[0] if cwe_list else ""
                enr = enrich_for_cwe(cwe) or {}
                conf = _SEV_CONF.get((extra.get("severity") or "WARNING").upper(), "potential")
                start = r.get("start", {})
                end = r.get("end", {})
                line = start.get("line", 0)
                end_line = end.get("line", line)
                # Slice evidence from the real source, never from extra.lines.
                snippet, snip_err = snippet_from_source(src_lines, line, end_line)
                raw = (extra.get("lines", "") or "").strip("\n")
                matched = "" if raw == SEMGREP_PLACEHOLDER else raw
                if not matched and snippet:
                    hit = [s["text"] for s in snippet if s["hit"]]
                    matched = "\n".join(hit)
                owasp = meta.get("owasp", []) or []
                check_id = str(r.get("check_id", "semgrep"))
                msg = extra.get("message", "Semgrep finding")
                out.append(
                    {
                        "rule_id": check_id.split(".")[-1],
                        "rule_source": check_id,
                        "name": msg[:140],
                        "cwe": cwe,
                        "language": language,
                        "line": line,
                        "end_line": end_line,
                        "start_col": start.get("col"),
                        "end_col": end.get("col"),
                        "matched_text": matched[:300],
                        "confidence": conf,
                        "confidence_label": CONF_LABEL[conf],
                        "snippet": snippet,
                        "snippet_error": snip_err,
                        "description": msg,
                        "why_dangerous": enr.get("exploit", "") or meta.get("exploit", ""),
                        "preconditions": "",
                        "taint_evidence": None,
                        "test_procedure": "",
                        "exploit_template": enr.get("payload", "") or meta.get("payload", ""),
                        "remediation": enr.get("patch", "") or meta.get("patch", "")
                        or (extra.get("fix", "") or ""),
                        "why_patch_works": "",
                        "regression_test": "",
                        "references": meta.get("references", []) or [],
                        "limitations": ("Reported by Semgrep (" + ", ".join(owasp) + ").")
                        if owasp else "Reported by Semgrep.",
                        "engine": "semgrep",
                    }
                )
            return out, f"Semgrep ran with the bundled ruleset ({len(out)} finding(s))."
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
        return [], f"Semgrep unavailable: {type(e).__name__}"
