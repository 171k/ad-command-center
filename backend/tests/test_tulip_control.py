"""Tulip config control plane: strict validation + request artifact writing."""
import json

import pytest

from app import tulip_control as tc

GOOD = {
    "tick_start": "2026-11-17T09:00:00Z", "tick_length": 120000,
    "flag_regex": "[A-Z0-9]{31}=", "vm_ip": "10.0.0.1", "team_id": 2,
    "services": [{"name": "web-1", "ip": "10.0.0.1", "port": 8080}],
}


def test_validate_accepts_good_config():
    out = tc.validate_config(GOOD)
    assert out["services"][0]["port"] == 8080
    assert out["vm_ip"] == "10.0.0.1"


@pytest.mark.parametrize("mut", [
    {"tick_start": "not-a-date"},
    {"tick_length": 10},                 # too small
    {"tick_length": "abc"},
    {"flag_regex": ""},
    {"flag_regex": 'has"quote'},         # quote would break .env
    {"flag_regex": "[unclosed"},         # not a valid regex
    {"vm_ip": "999.1.1.1"},
    {"services": []},                    # at least one required
    {"services": [{"name": "x", "ip": "bad", "port": 80}]},
    {"services": [{"name": "x", "ip": "10.0.0.1", "port": 99999}]},
    {"services": [{"name": "bad;name", "ip": "10.0.0.1", "port": 80}]},
])
def test_validate_rejects_bad(mut):
    bad = {**GOOD, **mut}
    with pytest.raises(tc.ConfigError):
        tc.validate_config(bad)


def test_save_writes_config_and_request(tmp_path, monkeypatch):
    monkeypatch.setattr(tc, "CONTROL_DIR", tmp_path)
    monkeypatch.setattr(tc, "CONFIG_FILE", tmp_path / "tulip-config.json")
    monkeypatch.setattr(tc, "REQUEST_FILE", tmp_path / "tulip-rebuild.request")
    monkeypatch.setattr(tc, "STATUS_FILE", tmp_path / "tulip-status.json")
    res = tc.save_and_request_rebuild(GOOD, by="itik")
    assert res["request_id"]
    cfg = json.loads((tmp_path / "tulip-config.json").read_text())
    assert cfg["request_id"] == res["request_id"]
    assert cfg["requested_by"] == "itik"
    req = json.loads((tmp_path / "tulip-rebuild.request").read_text())
    assert req["request_id"] == res["request_id"]
    status = json.loads((tmp_path / "tulip-status.json").read_text())
    assert status["state"] == "queued"


def test_save_rejects_bad_before_writing(tmp_path, monkeypatch):
    monkeypatch.setattr(tc, "CONTROL_DIR", tmp_path)
    monkeypatch.setattr(tc, "REQUEST_FILE", tmp_path / "tulip-rebuild.request")
    with pytest.raises(tc.ConfigError):
        tc.save_and_request_rebuild({**GOOD, "vm_ip": "nope"}, by="itik")
    assert not (tmp_path / "tulip-rebuild.request").exists()
