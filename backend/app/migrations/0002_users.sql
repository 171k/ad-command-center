-- Per-user accounts (shared data stays shared). The single shared `account`
-- row is preserved and migrated into the 'itik' user so that login keeps working
-- with the password already set. Other team users are seeded by the admin CLI
-- (python -m app.admin seed-users) so their default password never lives in git.

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT,
    totp_secret     TEXT,
    totp_enabled    INTEGER NOT NULL DEFAULT 0,
    disabled        INTEGER NOT NULL DEFAULT 0,
    password_set_at TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Link sessions to a user (nullable for legacy rows).
ALTER TABLE sessions ADD COLUMN user_id INTEGER;

-- Carry the existing shared account over to 'itik' (keeps that password + TOTP).
INSERT OR IGNORE INTO users(username, password_hash, totp_secret, totp_enabled, password_set_at, created_at)
SELECT 'itik', password_hash, totp_secret, totp_enabled, password_set_at, created_at
FROM account WHERE id = 1 AND password_hash IS NOT NULL;
