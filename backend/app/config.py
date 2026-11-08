"""Centralized configuration loaded from environment / .env.

No secrets are hardcoded. The initial account password is NEVER read from here;
it is set via the admin CLI (scripts) and stored only as an Argon2id hash.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent  # backend/
REPO_DIR = BASE_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(REPO_DIR / ".env"), env_prefix="ADCC_", extra="ignore"
    )

    # --- Core ---
    app_name: str = "A&D Command Center"
    environment: str = "development"  # development | production
    secret_key: str = Field(
        default="dev-insecure-change-me",
        description="Signing key for CSRF/session tokens. Override in production.",
    )

    # --- Paths ---
    data_dir: Path = REPO_DIR / "data"
    db_path: Path = REPO_DIR / "data" / "adcc.db"
    upload_dir: Path = REPO_DIR / "data" / "uploads"
    pcap_dir: Path = REPO_DIR / "data" / "pcaps"
    tools_dir: Path = REPO_DIR / "data" / "tools"       # hosted tool artifacts
    pwn_dir: Path = REPO_DIR / "data" / "pwn"           # uploaded challenge binaries
    max_tool_artifact_bytes: int = 500 * 1024 * 1024   # 500MB per artifact
    max_pwn_binary_bytes: int = 64 * 1024 * 1024        # 64MB per binary

    # --- Auth / sessions ---
    session_ttl_seconds: int = 60 * 60 * 12  # 12h sliding
    session_cookie_name: str = "adcc_session"
    csrf_cookie_name: str = "adcc_csrf"
    cookie_secure: bool = False  # True behind HTTPS (production)
    cookie_samesite: str = "lax"
    # Comma-separated Host allowlist (TrustedHostMiddleware). "*" disables the check.
    allowed_hosts: str = "*"
    login_max_attempts: int = 8
    login_window_seconds: int = 300

    # --- SOC / ingestion limits (tuned for ~4GB VPS) ---
    max_events: int = 500_000
    event_retention_days: int = 14
    max_payload_display_bytes: int = 64 * 1024
    ingest_queue_max: int = 10_000
    correlation_window_seconds: int = 600
    worker_concurrency: int = 2

    # --- Uploads ---
    max_upload_bytes: int = 50 * 1024 * 1024  # 50MB pcap cap
    max_total_pcap_bytes: int = 2 * 1024 * 1024 * 1024  # 2GB

    # --- Recon / outbound safety ---
    recon_timeout_seconds: float = 5.0
    recon_max_concurrency: int = 4

    # --- Feature gates (require explicit operator opt-in) ---
    enable_exploit_runner: bool = False
    enable_task_execution: bool = False
    enable_pwn_exec: bool = False      # run uploaded binaries/exploits (needs sandbox worker)
    enable_scheduled_jobs: bool = False
    enable_demo_data: bool = False

    # Usernames with admin access (session management, audit log, feature gates).
    admin_users: str = "itik"

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @property
    def admin_user_set(self) -> set[str]:
        return {u.strip().lower() for u in self.admin_users.split(",") if u.strip()}


@lru_cache
def get_settings() -> Settings:
    s = get_settings_uncached()
    return s


def get_settings_uncached() -> Settings:
    s = Settings()
    for d in (s.data_dir, s.upload_dir, s.pcap_dir, s.tools_dir, s.pwn_dir):
        d.mkdir(parents=True, exist_ok=True)
    return s
