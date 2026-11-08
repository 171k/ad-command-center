-- Pwn Solver cases: uploaded challenge binaries (stored on disk), their static
-- analysis, notes and saved exploit scripts. Binaries are NEVER executed by the
-- web app; execution happens only in a separate, gated local sandbox worker.

CREATE TABLE IF NOT EXISTS pwn_cases (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    filename      TEXT,
    size_bytes    INTEGER,
    sha256        TEXT,
    storage_path  TEXT,                    -- relative to pwn_dir
    arch          TEXT,
    analysis      TEXT,                    -- JSON static-analysis result
    notes         TEXT,
    label         TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS pwn_scripts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL REFERENCES pwn_cases(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    body        TEXT NOT NULL,
    label       TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_pwn_scripts_case ON pwn_scripts(case_id);
