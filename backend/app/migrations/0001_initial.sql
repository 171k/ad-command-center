-- A&D Command Center, initial schema
-- One shared account; multiple concurrent sessions; optional session labels.

-- ---------- Account & auth ----------
CREATE TABLE IF NOT EXISTS account (
    id              INTEGER PRIMARY KEY CHECK (id = 1),   -- single shared account
    username        TEXT NOT NULL DEFAULT 'team',
    password_hash   TEXT,                                 -- Argon2id; NULL until setup
    totp_secret     TEXT,                                 -- optional MFA
    totp_enabled    INTEGER NOT NULL DEFAULT 0,
    password_set_at TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT OR IGNORE INTO account(id) VALUES (1);

CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,          -- opaque random token (hashed at rest)
    label         TEXT,                      -- "Player 1".."Substitute" (not identity)
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at  TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at    TEXT NOT NULL,
    user_agent    TEXT,
    ip            TEXT,
    revoked       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS login_attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT,
    success    INTEGER NOT NULL,
    at         TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_at ON login_attempts(at);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         TEXT NOT NULL DEFAULT (datetime('now')),
    session_id TEXT,
    label      TEXT,
    ip         TEXT,
    action     TEXT NOT NULL,
    detail     TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);

-- ---------- Config (key/value) ----------
CREATE TABLE IF NOT EXISTS app_config (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ---------- Services & authorized targets ----------
CREATE TABLE IF NOT EXISTS services (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    host         TEXT NOT NULL,
    port         INTEGER,
    protocol     TEXT NOT NULL DEFAULT 'tcp',   -- tcp | http | https
    description  TEXT,
    owner        TEXT NOT NULL DEFAULT 'ours',  -- ours | opponent
    authorized   INTEGER NOT NULL DEFAULT 0,    -- allowlist flag for active probing
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host);

CREATE TABLE IF NOT EXISTS service_health (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id   INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    status       TEXT NOT NULL,                 -- online | offline | unknown
    latency_ms   REAL,
    detail       TEXT,
    checked_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_health_service ON service_health(service_id, checked_at);

-- ---------- Findings (shared, cross-workspace) ----------
CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    title         TEXT NOT NULL,
    description   TEXT,
    category      TEXT,                          -- attack|defense|automation|soc
    source        TEXT,                          -- originating workspace
    service_id    INTEGER REFERENCES services(id) ON DELETE SET NULL,
    status        TEXT NOT NULL DEFAULT 'open',  -- open|investigating|resolved
    severity      TEXT NOT NULL DEFAULT 'medium',
    evidence      TEXT,                          -- JSON
    refs          TEXT,                          -- JSON links (offense/vuln/script ids)
    label         TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

CREATE TABLE IF NOT EXISTS finding_notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    body       TEXT NOT NULL,
    label      TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ---------- Defense: analysis results ----------
CREATE TABLE IF NOT EXISTS analyses (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    title        TEXT,
    language     TEXT,
    source_code  TEXT NOT NULL,
    engine       TEXT NOT NULL,                  -- builtin | semgrep | combined
    result       TEXT NOT NULL,                  -- JSON findings array
    label        TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ---------- Scripts / exploit templates ----------
CREATE TABLE IF NOT EXISTS scripts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    language     TEXT NOT NULL DEFAULT 'python',
    category     TEXT NOT NULL DEFAULT 'general',
    body         TEXT NOT NULL,
    notes        TEXT,
    tags         TEXT,                           -- JSON array
    kind         TEXT NOT NULL DEFAULT 'script', -- script | exploit_template
    label        TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scripts_cat ON scripts(category);

CREATE TABLE IF NOT EXISTS script_revisions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    script_id  INTEGER NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
    body       TEXT NOT NULL,
    note       TEXT,
    label      TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ---------- Flags ----------
CREATE TABLE IF NOT EXISTS flags (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    value_hash   TEXT NOT NULL UNIQUE,           -- dedup without storing raw in index
    value        TEXT NOT NULL,                  -- raw flag (kept out of logs/git)
    service_id   INTEGER REFERENCES services(id) ON DELETE SET NULL,
    status       TEXT NOT NULL DEFAULT 'pending',-- pending|accepted|rejected|duplicate
    response     TEXT,
    label        TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    submitted_at TEXT
);

-- ---------- SOC: sensors, events, offenses ----------
CREATE TABLE IF NOT EXISTS sensors (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL,                   -- ingestion credential (hashed)
    kind        TEXT NOT NULL DEFAULT 'suricata',
    last_seen   TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,                 -- event timestamp (ISO)
    received_at   TEXT NOT NULL DEFAULT (datetime('now')),
    source        TEXT,                          -- suricata|pcap|accesslog|...
    sensor_id     INTEGER REFERENCES sensors(id) ON DELETE SET NULL,
    src_ip        TEXT,
    src_port      INTEGER,
    dest_ip       TEXT,
    dest_port     INTEGER,
    proto         TEXT,
    service_id    INTEGER REFERENCES services(id) ON DELETE SET NULL,
    flow_id       TEXT,
    tx_id         TEXT,
    event_type    TEXT,                          -- alert|http|flow|fileinfo
    category      TEXT,                          -- normalized attack technique
    signature     TEXT,
    signature_id  INTEGER,
    severity      INTEGER,
    http_method   TEXT,
    http_url      TEXT,
    http_status   INTEGER,
    http_host     TEXT,
    payload       TEXT,                          -- decoded/observed payload (bounded)
    payload_b64   TEXT,                          -- original bytes when present
    raw           TEXT,                          -- original JSON record (bounded)
    fingerprint   TEXT,                          -- normalized payload fingerprint
    offense_id    INTEGER REFERENCES offenses(id) ON DELETE SET NULL,
    outcome       TEXT                           -- per-event outcome hint
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_dest ON events(dest_ip, dest_port);
CREATE INDEX IF NOT EXISTS idx_events_cat ON events(category);
CREATE INDEX IF NOT EXISTS idx_events_offense ON events(offense_id);
CREATE INDEX IF NOT EXISTS idx_events_flow ON events(flow_id);

CREATE TABLE IF NOT EXISTS offenses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    category        TEXT NOT NULL,               -- attack technique
    service_id      INTEGER REFERENCES services(id) ON DELETE SET NULL,
    dest_ip         TEXT,
    dest_port       INTEGER,
    src_ip          TEXT,                         -- attacker identifier
    outcome         TEXT NOT NULL DEFAULT 'attempted', -- confirmed|possible|attempted|blocked
    severity        TEXT NOT NULL DEFAULT 'medium',
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    event_count     INTEGER NOT NULL DEFAULT 0,
    distinct_payloads INTEGER NOT NULL DEFAULT 0,
    top_event_id    INTEGER,                      -- most suspicious / strongest evidence
    evidence        TEXT,                          -- JSON evidence summary
    status          TEXT NOT NULL DEFAULT 'new',  -- new|investigating|resolved|suppressed
    notes_count     INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_offenses_outcome ON offenses(outcome, last_seen);
CREATE INDEX IF NOT EXISTS idx_offenses_key ON offenses(category, dest_ip, dest_port, src_ip);

CREATE TABLE IF NOT EXISTS offense_notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    offense_id INTEGER NOT NULL REFERENCES offenses(id) ON DELETE CASCADE,
    body       TEXT NOT NULL,
    label      TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ---------- Automation jobs ----------
CREATE TABLE IF NOT EXISTS jobs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    kind         TEXT NOT NULL,                  -- health_check | script | recon
    config       TEXT,                           -- JSON
    schedule     TEXT,                           -- cron-like / interval secs
    enabled      INTEGER NOT NULL DEFAULT 0,
    last_run_at  TEXT,
    last_status  TEXT,
    next_run_at  TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS executions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id       INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
    kind         TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'queued', -- queued|running|done|error|cancelled
    exit_code    INTEGER,
    stdout       TEXT,
    stderr       TEXT,
    duration_ms  REAL,
    label        TEXT,
    started_at   TEXT,
    finished_at  TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
