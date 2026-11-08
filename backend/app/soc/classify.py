"""Outcome classification with transparent, defensible evidence.

Rules (deliberately conservative, see SIEM.md):

CONFIRMED  only with direct, attributable application-level proof tied to the
           request (an instrumented service recording an unauthorized action,
           a verified flag read, a returned command-output marker). NEVER from
           an IDS signature, a 200 or a 500 alone.
POSSIBLE   a suspicious exploit payload PLUS a corroborating response anomaly
           (reflected payload, SQL error leakage, template-evaluation result,
           command-output fragment) that matches expected exploit behaviour.
BLOCKED    evidence a control stopped it (403/406/429, WAF action=blocked) and
           no contradictory success evidence.
ATTEMPTED  an attack pattern was seen but the outcome cannot be determined.

Returns (outcome, evidence) where evidence is a list of {signal, detail}.
"""
from __future__ import annotations

import re

# Response-body signals that an injection likely took effect.
_SQL_ERRORS = re.compile(r"(SQL syntax|mysql_fetch|ORA-\d{5}|SQLiteException|PG::|unterminated quoted string|near \")", re.I)
_CMD_OUTPUT = re.compile(r"(uid=\d+\(|gid=\d+\(|root:.*:0:0:|/bin/bash|Directory of |volume serial number)", re.I)

OUTCOME_RANK = {"attempted": 0, "blocked": 1, "possible": 2, "confirmed": 3}


def classify(ev: dict, rec: dict | None = None) -> tuple[str, list[dict]]:
    rec = rec or {}
    evidence: list[dict] = []
    category = ev.get("category", "other")
    payload = (ev.get("payload") or "")
    resp_body = str(rec.get("response_body") or rec.get("resp_body") or "")
    status = ev.get("http_status")

    # 1) CONFIRMED: explicit attributable proof only.
    proof = rec.get("app_proof") or rec.get("proof")
    if proof:
        evidence.append({
            "signal": "application_proof",
            "detail": f"Instrumented evidence of unauthorized action: {str(proof)[:200]}",
        })
        return "confirmed", evidence

    # command-output fragment echoed back is strong, attributable application evidence
    if resp_body and _CMD_OUTPUT.search(resp_body) and category == "command_injection":
        evidence.append({
            "signal": "command_output_in_response",
            "detail": "Response body contains command-output markers (e.g. uid=…) matching the injected command.",
        })
        return "confirmed", evidence

    # 2) POSSIBLE: suspicious payload + corroborating response anomaly.
    attack_payload = category not in ("other", "scanner", "ids_alert")

    if attack_payload and resp_body:
        if category == "sql_injection" and _SQL_ERRORS.search(resp_body):
            evidence.append({"signal": "sql_error_leak", "detail": "Database error string leaked in response."})
            return "possible", evidence
        # reflected XSS: the exact payload appears unencoded in the response
        if category == "xss" and payload and payload[:40] in resp_body and "<" in payload:
            evidence.append({"signal": "reflected_payload", "detail": "Injected markup reflected unencoded in response."})
            return "possible", evidence
        # SSTI arithmetic: {{7*7}} -> 49 appears where the literal does not
        ssti = re.search(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}", payload)
        if category == "ssti" and ssti:
            product = str(int(ssti.group(1)) * int(ssti.group(2)))
            if product in resp_body and f"{ssti.group(1)}*{ssti.group(2)}" not in resp_body:
                evidence.append({"signal": "template_evaluated", "detail": f"Template math evaluated: product {product} present in response."})
                return "possible", evidence

    # anomalous 500 together with an injection payload is suggestive but not proof
    if attack_payload and status == 500:
        evidence.append({"signal": "server_error_with_payload", "detail": "HTTP 500 returned while an injection payload was present (suggestive, not proof)."})
        return "possible", evidence

    # 3) BLOCKED
    if ev.get("outcome") == "blocked" or status in (403, 406, 429):
        evidence.append({"signal": "control_block", "detail": f"Request met a control (HTTP {status}); treated as blocked."})
        return "blocked", evidence

    # 4) ATTEMPTED / UNKNOWN
    if attack_payload:
        evidence.append({"signal": "attack_pattern", "detail": f"{category} pattern detected; outcome telemetry insufficient to confirm."})
    else:
        evidence.append({"signal": "observed", "detail": "Event recorded; no exploit pattern or outcome signal."})
    return "attempted", evidence


def merge_outcome(current: str, new: str) -> str:
    """Upgrade an offense's outcome only; never silently downgrade."""
    if OUTCOME_RANK.get(new, 0) > OUTCOME_RANK.get(current, 0):
        return new
    return current
