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

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

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
                "name": rule.name,
                "cwe": rule.cwe,
                "language": lang,
                "line": line_no,
                "matched_text": m.group(0).strip()[:300],
                "confidence": confidence,
                "confidence_label": CONF_LABEL[confidence],
                "snippet": _snippet(code_lines, line_no),
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
            findings.extend(sg)
            engine_used = "combined"
        semgrep_note = note
    elif use_semgrep:
        semgrep_note = "Semgrep not installed; used built-in rules only."

    findings.sort(key=lambda f: (-CONF_ORDER.get(f["confidence"], 0), f["line"]))

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
            "No rule matched. This does NOT prove the code is secure — it only "
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


def _run_semgrep(code: str, language: str) -> tuple[list[dict], str]:
    """Run local Semgrep with bundled custom rules if present. Bounded, offline."""
    import json

    ext = {"python": ".py", "javascript": ".js", "php": ".php", "java": ".java",
           "c": ".c", "cpp": ".cpp", "shell": ".sh"}.get(language, ".txt")
    rules_dir = Path(__file__).resolve().parent / "semgrep_rules"
    try:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / f"snippet{ext}"
            src.write_text(code, encoding="utf-8")
            if not rules_dir.exists():
                # Never use --config auto (it fetches from the registry). Offline-only.
                return [], "Semgrep installed but no local ruleset bundled; used built-in rules."
            cmd = ["semgrep", "--json", "--quiet", "--timeout", "15",
                   "--metrics=off", "--config", str(rules_dir), str(src)]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if proc.returncode not in (0, 1):
                return [], f"Semgrep exited {proc.returncode}: {proc.stderr[:200]}"
            data = json.loads(proc.stdout or "{}")
            out = []
            for r in data.get("results", []):
                out.append(
                    {
                        "rule_id": r.get("check_id", "semgrep"),
                        "name": r.get("extra", {}).get("message", "Semgrep finding")[:120],
                        "cwe": ";".join(r.get("extra", {}).get("metadata", {}).get("cwe", []) or []),
                        "language": language,
                        "line": r.get("start", {}).get("line", 0),
                        "matched_text": (r.get("extra", {}).get("lines", "") or "")[:300],
                        "confidence": "potential",
                        "confidence_label": CONF_LABEL["potential"],
                        "snippet": [],
                        "description": r.get("extra", {}).get("message", ""),
                        "why_dangerous": "",
                        "preconditions": "",
                        "taint_evidence": None,
                        "test_procedure": "",
                        "exploit_template": "",
                        "remediation": r.get("extra", {}).get("fix", "") or "",
                        "why_patch_works": "",
                        "regression_test": "",
                        "references": r.get("extra", {}).get("metadata", {}).get("references", []) or [],
                        "limitations": "Reported by Semgrep.",
                        "engine": "semgrep",
                    }
                )
            return out, f"Semgrep ran ({len(out)} findings)."
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
        return [], f"Semgrep unavailable: {type(e).__name__}"
