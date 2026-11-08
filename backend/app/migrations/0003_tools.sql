-- Server-hosted tool repository: a first-party catalog of approved tools so the
-- team can install without GitHub/public registries during the competition.
-- Artifact bytes live on the filesystem (data/tools/), not as DB blobs; the DB
-- holds metadata + SHA-256 for integrity verification.

CREATE TABLE IF NOT EXISTS tools (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    slug            TEXT NOT NULL UNIQUE,         -- e.g. "pwntools"
    name            TEXT NOT NULL,                -- display name
    category        TEXT NOT NULL,                -- Web Security, Binary Exploitation, ...
    version         TEXT,                         -- pinned version
    description     TEXT,
    license         TEXT,                         -- e.g. MIT, BSD-3, GPL-2.0
    provenance      TEXT,                         -- upstream source URL / note
    os_support      TEXT,                         -- JSON list: ["kali","ubuntu","wsl2","windows"]
    dependencies    TEXT,                         -- JSON list
    install         TEXT,                         -- JSON {os: "commands/notes"}
    tags            TEXT,                         -- JSON list
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_tools_cat ON tools(category);

CREATE TABLE IF NOT EXISTS tool_artifacts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_id       INTEGER NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
    filename      TEXT NOT NULL,
    os            TEXT,                            -- target OS (or 'any')
    arch          TEXT,                            -- x86_64, aarch64, any
    size_bytes    INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    storage_path  TEXT NOT NULL,                   -- relative to tools_dir
    notes         TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_artifacts_tool ON tool_artifacts(tool_id);
