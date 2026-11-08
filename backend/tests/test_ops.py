"""Ops upgrade: RCE script generator, tcpdump builder, guides, scope enforcement."""
import ast

import pytest

from app.ops import generators as g


@pytest.mark.parametrize("proto", ["requests", "http", "tcp", "pwntools"])
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_rce_scripts_are_valid_python(proto, method):
    spec = {"protocol": proto, "name": "x y", "host": "svc.test", "port": 443, "tls": True,
            "path": "/i.php", "method": method, "params": {"page": "{{PAYLOAD}}"},
            "payload": "../../etc/passwd", "expected": "root:x:", "timeout": 8}
    out = g.rce_script(spec)
    assert out["filename"] == "x_y.py"
    ast.parse(out["script"])  # must be syntactically valid
    assert "AUTHORISED TARGETS ONLY" in out["script"]


def test_rce_requires_host():
    with pytest.raises(ValueError):
        g.rce_script({"protocol": "tcp", "host": ""})


def test_rce_unknown_protocol():
    with pytest.raises(ValueError):
        g.rce_script({"protocol": "smtp", "host": "x.test"})


def test_tcpdump_bounded_command():
    t = g.tcpdump_command({"interface": "ens5", "ports": [8080, 80], "protocol": "tcp",
                           "exclude_ssh": True, "rotate_seconds": 30, "keep_files": 60,
                           "out_prefix": "game"})
    cmd = t["command"]
    assert "tcpdump -i ens5" in cmd
    assert "-G 30" in cmd and "-W 60" in cmd            # bounded rotation
    assert "not port 22" in t["bpf"]                     # ssh excluded
    assert "port 8080 or port 80" in t["bpf"]
    assert "%Y%m%d" in cmd                               # rotation needs strftime output
    assert t["rotate_command"].count("-z") == 1          # upload hook in rotate variant


def test_tcpdump_injection_safe():
    t = g.tcpdump_command({"interface": "ens5; rm -rf /", "hosts": ["1.2.3.4; evil"]})
    assert "rm -rf" not in t["command"]                  # interface token sanitised
    assert "evil" not in t["bpf"]                        # bad host rejected


# ---- endpoints ----

def _add_authorised(client, headers, host):
    return client.post("/api/services", json={
        "name": "t", "host": host, "port": 443, "protocol": "https",
        "owner": "opponent", "authorized": True}, headers=headers)


def test_guides_list_and_get(auth):
    client, headers = auth
    r = client.get("/api/ops/guides", headers=headers)
    assert r.status_code == 200
    ids = [x["id"] for x in r.json()["items"]]
    assert "packet-capture" in ids and "persistence-investigation" in ids
    one = client.get("/api/ops/guides/packet-capture", headers=headers)
    assert one.status_code == 200
    assert one.json()["sections"]
    assert client.get("/api/ops/guides/nope", headers=headers).status_code == 404


def test_guides_search(auth):
    client, headers = auth
    r = client.get("/api/ops/guides?q=authorized_keys", headers=headers)
    ids = [x["id"] for x in r.json()["items"]]
    assert "persistence-reference" in ids


def test_rce_template_rejects_unauthorised_target(auth):
    client, headers = auth
    r = client.post("/api/ops/rce-template",
                    json={"protocol": "requests", "host": "not-registered.test", "port": 443},
                    headers=headers)
    assert r.status_code == 403


def test_rce_template_generates_for_authorised_target(auth):
    client, headers = auth
    _add_authorised(client, headers, "svc.authorised.test")
    r = client.post("/api/ops/rce-template",
                    json={"protocol": "requests", "host": "svc.authorised.test", "port": 443,
                          "tls": True, "path": "/", "payload": "x"},
                    headers=headers)
    assert r.status_code == 200
    assert r.json()["filename"].endswith(".py")
    ast.parse(r.json()["script"])


def test_tcpdump_endpoint(auth):
    client, headers = auth
    r = client.post("/api/ops/tcpdump", json={"interface": "eth0", "ports": [1337]}, headers=headers)
    assert r.status_code == 200
    assert "tcpdump -i eth0" in r.json()["command"]
