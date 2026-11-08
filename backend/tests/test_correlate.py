"""Evidence-based correlation: link findings only on shared security symbols or
import edges; never invent a chain; keep unrelated findings separate."""
from app.analyzer.correlate import build_related


def _f(line, cwe, text, name="x"):
    return {"line": line, "cwe": cwe, "name": name,
            "matched_text": text, "snippet": [{"n": line, "text": text, "hit": True}]}


def test_link_on_shared_security_symbol():
    fes = [
        {"path": "a.js", "findings": [_f(3, "CWE-200", "props: { SIGNING_SECRET }")]},
        {"path": "b.js", "findings": [_f(9, "CWE-321", "createHmac(sha256, SIGNING_SECRET)")]},
    ]
    groups = build_related(fes, {"a.js": "", "b.js": ""})
    assert len(groups) == 1
    assert any("SIGNING_SECRET" in e for e in groups[0]["evidence"])
    # integrity (200) + crypto-key (321) share a secret -> both are integrity bucket,
    # still grouped; members cover both files.
    paths = {m["path"] for m in groups[0]["members"]}
    assert paths == {"a.js", "b.js"}


def test_link_on_import_edge_and_chain_label():
    sources = {
        "docs.js": 'import { verify } from "./token";\nfs.readFileSync(p);',
        "token.js": 'export function verify(){}',
    }
    fes = [
        {"path": "docs.js", "findings": [_f(2, "CWE-22", "fs.readFileSync(target)")]},
        {"path": "token.js", "findings": [_f(5, "CWE-285", "role = req.body.role")]},
    ]
    groups = build_related(fes, sources)
    assert len(groups) == 1
    assert any("import" in e.lower() for e in groups[0]["evidence"])
    # access-control (22/285) + ... here both access bucket; label still set.
    assert groups[0]["label"]


def test_integrity_plus_access_label():
    sources = {"a.js": 'import "./b";', "b.js": ""}
    fes = [
        {"path": "a.js", "findings": [_f(1, "CWE-321", "hmac key authToken")]},
        {"path": "b.js", "findings": [_f(1, "CWE-22", "path authToken traversal")]},
    ]
    groups = build_related(fes, sources)
    assert len(groups) == 1
    assert "enable" in groups[0]["label"].lower()        # conservative chain phrasing


def test_unrelated_findings_stay_separate():
    # No shared symbol, no import -> no group.
    fes = [
        {"path": "a.js", "findings": [_f(1, "CWE-89", "execute(query)")]},
        {"path": "b.js", "findings": [_f(1, "CWE-79", "innerHTML = data")]},
    ]
    groups = build_related(fes, {"a.js": "", "b.js": ""})
    assert groups == []


def test_generic_identifier_does_not_link():
    # 'value' is a stop word / non-security; must not create a spurious chain.
    fes = [
        {"path": "a.js", "findings": [_f(1, "CWE-89", "const value = execute(x)")]},
        {"path": "b.js", "findings": [_f(1, "CWE-79", "const value = render(y)")]},
    ]
    assert build_related(fes, {"a.js": "", "b.js": ""}) == []
