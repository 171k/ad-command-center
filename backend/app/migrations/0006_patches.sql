-- Defense patch management: record a proposed source patch for a finding, review
-- it, record security + functional validation results separately, and track its
-- lifecycle. Records are shared across teammates; `version` is an optimistic lock
-- so concurrent edits do not silently overwrite each other.

CREATE TABLE IF NOT EXISTS patches (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    title              TEXT NOT NULL,
    service_id         INTEGER,              -- optional link to services(id)
    finding_id         TEXT,                 -- analyzer rule id / finding reference
    cwe                TEXT,
    filename           TEXT,
    affected_lines     TEXT,                 -- e.g. "12-15"
    language           TEXT,
    original_code      TEXT NOT NULL DEFAULT '',
    patched_code       TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL DEFAULT 'suggested',
    reviewer           TEXT,
    -- validation (tracked separately: security != functional)
    security_status    TEXT NOT NULL DEFAULT 'pending',   -- pending|pass|fail|na
    security_notes     TEXT,
    functional_status  TEXT NOT NULL DEFAULT 'pending',   -- pending|pass|fail|na
    functional_notes   TEXT,
    deployment_status  TEXT NOT NULL DEFAULT 'not_deployed', -- not_deployed|applied|verified|rolled_back
    rollback_ref       TEXT,
    notes              TEXT,
    version            INTEGER NOT NULL DEFAULT 1,
    label              TEXT,                 -- creator username
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
    updated_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now'))
);

CREATE INDEX IF NOT EXISTS idx_patches_status ON patches(status);
CREATE INDEX IF NOT EXISTS idx_patches_service ON patches(service_id);

-- Append-only audit of status/validation transitions for the patch timeline.
CREATE TABLE IF NOT EXISTS patch_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    patch_id    INTEGER NOT NULL,
    kind        TEXT NOT NULL,    -- status | validation | note | rollback
    detail      TEXT,
    label       TEXT,
    at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
    FOREIGN KEY (patch_id) REFERENCES patches(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_patch_events_patch ON patch_events(patch_id);
