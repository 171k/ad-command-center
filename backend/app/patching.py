"""Deterministic patch diffing + a server-validated status workflow.

No execution of user code. We only diff text and enforce the lifecycle:
    suggested -> reviewed -> tested -> applied -> verified
with Rejected / Failed / Rolled Back as alternative outcomes. Security and
functional validation are tracked SEPARATELY: a passing security check never
implies the service still works, so 'verified' requires both to pass.
"""
from __future__ import annotations

import difflib

VALID_STATUSES = {
    "suggested", "reviewed", "tested", "applied", "verified",
    "rejected", "failed", "rolled_back",
}
VALIDATION_STATUSES = {"pending", "pass", "fail", "na"}

# Allowed status transitions (server-enforced).
TRANSITIONS: dict[str, set[str]] = {
    "suggested": {"reviewed", "rejected"},
    "reviewed": {"tested", "rejected", "suggested"},
    "tested": {"applied", "failed", "rejected", "reviewed"},
    "applied": {"verified", "rolled_back", "failed"},
    "verified": {"rolled_back"},
    "rejected": {"suggested"},      # allow re-opening a rejected patch
    "failed": {"suggested", "tested"},
    "rolled_back": {"suggested"},
}

# deployment_status derived from the lifecycle status.
_DEPLOY_FOR_STATUS = {
    "applied": "applied",
    "verified": "verified",
    "rolled_back": "rolled_back",
}


def can_transition(frm: str, to: str) -> bool:
    return to in TRANSITIONS.get(frm, set())


def transition_error(frm: str, to: str, patch: dict) -> str | None:
    """Return an error message if the transition is not allowed, else None."""
    if to not in VALID_STATUSES:
        return f"Unknown status '{to}'."
    if frm == to:
        return None
    if not can_transition(frm, to):
        allowed = ", ".join(sorted(TRANSITIONS.get(frm, set()))) or "(none)"
        return f"Cannot move from '{frm}' to '{to}'. Allowed: {allowed}."
    if to == "verified":
        if patch.get("security_status") != "pass" or patch.get("functional_status") != "pass":
            return ("Cannot verify: both the security regression check AND the service "
                    "functional check must be recorded as 'pass' first.")
    return None


def deployment_status_for(status: str, current: str) -> str:
    return _DEPLOY_FOR_STATUS.get(status, current)


def unified_diff(original: str, patched: str, filename: str = "patch") -> str:
    o = (original or "").splitlines()
    p = (patched or "").splitlines()
    fn = filename or "patch"
    diff = difflib.unified_diff(o, p, fromfile=f"a/{fn}", tofile=f"b/{fn}", lineterm="")
    return "\n".join(diff)


def side_by_side(original: str, patched: str) -> list[dict]:
    """Aligned rows for a side-by-side view.

    Each row: {left, right, left_no, right_no, type} where type is
    equal | add | del | mod.
    """
    o = (original or "").splitlines()
    p = (patched or "").splitlines()
    sm = difflib.SequenceMatcher(a=o, b=p, autojunk=False)
    rows: list[dict] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                rows.append(_row(o[i1 + k], p[j1 + k], i1 + k + 1, j1 + k + 1, "equal"))
        elif tag == "replace":
            n = max(i2 - i1, j2 - j1)
            for k in range(n):
                left = o[i1 + k] if i1 + k < i2 else None
                right = p[j1 + k] if j1 + k < j2 else None
                rows.append(_row(left, right,
                                 (i1 + k + 1) if left is not None else None,
                                 (j1 + k + 1) if right is not None else None, "mod"))
        elif tag == "delete":
            for k in range(i2 - i1):
                rows.append(_row(o[i1 + k], None, i1 + k + 1, None, "del"))
        elif tag == "insert":
            for k in range(j2 - j1):
                rows.append(_row(None, p[j1 + k], None, j1 + k + 1, "add"))
    return rows


def _row(left, right, left_no, right_no, typ):
    return {"left": left, "right": right, "left_no": left_no, "right_no": right_no, "type": typ}


def diff_stats(original: str, patched: str) -> dict:
    added = removed = modified = 0
    for r in side_by_side(original, patched):
        if r["type"] == "add":
            added += 1
        elif r["type"] == "del":
            removed += 1
        elif r["type"] == "mod":
            modified += 1
    return {"added": added, "removed": removed, "modified": modified}
