"""Tulip config control plane (web app side).

The web app NEVER touches Docker. It only reads/writes small JSON artifacts in a
shared control directory (bind-mounted from the host). A separate, unprivileged
host-side agent (deploy/tulip/control-agent.py) watches that directory, renders
Tulip's .env / configurations.py and rebuilds Tulip, then writes status back.

This keeps the Docker socket out of the web app (see the project's security
constraints) while still giving a one-click "Save & Rebuild" from the browser.

All config values are validated strictly here before they are written, because
they end up in Tulip's env and in a generated Python config file.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import time
import uuid
from pathlib import Path

CONTROL_DIR = Path(os.environ.get("ADCC_CONTROL_DIR", "/control"))
CONFIG_FILE = CONTROL_DIR / "tulip-config.json"
REQUEST_FILE = CONTROL_DIR / "tulip-rebuild.request"
STATUS_FILE = CONTROL_DIR / "tulip-status.json"

_TICK_START_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}([+-]\d{2}:?\d{2}|Z)?$")
_NAME_RE = re.compile(r"^[A-Za-z0-9 _.\-]{1,40}$")

DEFAULT_CONFIG = {
    "tick_start": "2026-11-17T09:00:00Z",
    "tick_length": 120000,
    "flag_regex": "[A-Z0-9]{31}=",
    "vm_ip": "10.0.0.1",
    "team_id": 1,
    "services": [{"name": "service-1", "ip": "10.0.0.1", "port": 8080}],
}


class ConfigError(ValueError):
    pass


def _check_ip(v: str) -> str:
    try:
        ipaddress.ip_address(v)
    except ValueError as e:
        raise ConfigError(f"invalid IP: {v!r}") from e
    return v


def validate_config(data: dict) -> dict:
    """Return a cleaned, strictly-validated config or raise ConfigError."""
    if not isinstance(data, dict):
        raise ConfigError("config must be an object")

    tick_start = str(data.get("tick_start", "")).strip()
    if not _TICK_START_RE.match(tick_start):
        raise ConfigError("tick_start must be ISO-8601, e.g. 2026-11-17T09:00:00Z")

    try:
        tick_length = int(data.get("tick_length"))
    except (TypeError, ValueError) as e:
        raise ConfigError("tick_length must be an integer (milliseconds)") from e
    if not 1000 <= tick_length <= 3_600_000:
        raise ConfigError("tick_length must be between 1000 and 3600000 ms")

    flag_regex = str(data.get("flag_regex", "")).strip()
    if not 1 <= len(flag_regex) <= 200 or '"' in flag_regex or "\n" in flag_regex:
        raise ConfigError("flag_regex must be 1-200 chars with no quotes/newlines")
    try:
        re.compile(flag_regex)
    except re.error as e:
        raise ConfigError(f"flag_regex is not a valid regex: {e}") from e

    vm_ip = _check_ip(str(data.get("vm_ip", "")).strip())

    try:
        team_id = int(data.get("team_id"))
    except (TypeError, ValueError) as e:
        raise ConfigError("team_id must be an integer") from e
    if not 0 <= team_id <= 99999:
        raise ConfigError("team_id out of range")

    raw_services = data.get("services") or []
    if not isinstance(raw_services, list) or not raw_services:
        raise ConfigError("at least one service is required")
    if len(raw_services) > 64:
        raise ConfigError("too many services (max 64)")
    services = []
    for i, s in enumerate(raw_services):
        if not isinstance(s, dict):
            raise ConfigError(f"service #{i + 1} is malformed")
        name = str(s.get("name", "")).strip()
        if not _NAME_RE.match(name):
            raise ConfigError(f"service #{i + 1} name invalid (allowed: letters, digits, space . _ -)")
        ip = _check_ip(str(s.get("ip", "")).strip())
        try:
            port = int(s.get("port"))
        except (TypeError, ValueError) as e:
            raise ConfigError(f"service #{i + 1} port must be an integer") from e
        if not 1 <= port <= 65535:
            raise ConfigError(f"service #{i + 1} port out of range")
        services.append({"name": name, "ip": ip, "port": port})

    return {
        "tick_start": tick_start, "tick_length": tick_length,
        "flag_regex": flag_regex, "vm_ip": vm_ip, "team_id": team_id,
        "services": services,
    }


def read_config() -> dict:
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return dict(DEFAULT_CONFIG)


def read_status() -> dict:
    try:
        return json.loads(STATUS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"state": "unknown", "message": "No rebuild has run yet.",
                "request_id": None, "updated_at": None}


def save_and_request_rebuild(data: dict, by: str) -> dict:
    """Validate, persist the config, and drop a rebuild request for the agent."""
    clean = validate_config(data)
    CONTROL_DIR.mkdir(parents=True, exist_ok=True)
    request_id = uuid.uuid4().hex[:12]
    payload = {**clean, "request_id": request_id,
               "requested_at": int(time.time()), "requested_by": by}
    # Write config first, then the request trigger (so the agent never reads a
    # half-written config).
    tmp = CONFIG_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(tmp, CONFIG_FILE)
    REQUEST_FILE.write_text(json.dumps({"request_id": request_id,
                                        "requested_at": payload["requested_at"],
                                        "requested_by": by}), encoding="utf-8")
    try:
        os.chmod(CONFIG_FILE, 0o644)
        os.chmod(REQUEST_FILE, 0o644)
    except OSError:
        pass
    # Optimistic local status so the UI shows "queued" immediately.
    try:
        STATUS_FILE.write_text(json.dumps({
            "state": "queued", "request_id": request_id,
            "message": "Rebuild requested; waiting for the host agent.",
            "updated_at": int(time.time())}), encoding="utf-8")
    except OSError:
        pass
    return {"request_id": request_id}
