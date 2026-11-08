-- Project scan jobs: a whole-service zip is extracted to a temp dir, statically
-- analyzed (built-in rules + Semgrep) and deleted. The source is NEVER executed.
-- Only the aggregated result is kept here, grouped by file.

CREATE TABLE IF NOT EXISTS scan_jobs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    filename       TEXT,
    status         TEXT NOT NULL DEFAULT 'queued',  -- queued | running | done | error
    phase          TEXT,                            -- human-readable progress note
    total_files    INTEGER DEFAULT 0,
    scanned_files  INTEGER DEFAULT 0,
    finding_count  INTEGER DEFAULT 0,
    result         TEXT,                            -- JSON: {files:[...], totals:{...}}
    error          TEXT,
    label          TEXT,                            -- username who started it
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
    updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now'))
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
