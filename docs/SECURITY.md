# Security model

This app holds sensitive material: exploit notes, vulnerable code, internal CTF
addresses, captured traffic, and flags. Security is built into the backend.

## Threat model

| Asset | Threat | Control |
|---|---|---|
| Shared password | Credential theft / brute force | Argon2id hashing; login rate limiting; optional TOTP; never logged or committed |
| Sessions | Hijack / CSRF | Opaque tokens stored only as SHA-256; HttpOnly + Secure + SameSite cookies; stateless HMAC CSRF on all mutations |
| API | Unauthorized access | Every data endpoint requires a valid session; no anonymous access; no registration |
| Database | Injection / exposure | Parameterized queries only; DB not exposed to the network; file perms via container user |
| Uploads (PCAP) | Malicious files / DoS | Magic-byte validation, size caps, processed by tshark out-of-process, never executed |
| Captured payloads | Stored XSS / code exec | Stored and rendered as **escaped text**; never interpreted as HTML/JS; never executed |
| Recon/exploit features | Abuse against out-of-scope hosts | Target allowlist (registry); active probing requires `authorized=1`; bounded timeouts/concurrency |
| Flags / secrets | Leakage | Raw flags kept out of logs and git; `.gitignore` blocks `.env`, DBs, PCAPs, flags |
| Sensors | Credential over-reach | Per-sensor bearer tokens (hashed), ingestion-only, no admin scope |

## Authentication & sessions

- One shared account (id = 1). Password set via the admin CLI, stored only as an
  Argon2id hash; rotation revokes all sessions.
- Sessions: random 256-bit token in an HttpOnly cookie; only its hash is stored,
  so a DB read cannot resume a session. Sliding 12h expiry; revoke-one / revoke-all.
- CSRF: double-submit with a stateless `HMAC(secret_key, session_hash)` token in a
  readable cookie, required as `X-CSRF-Token` on every non-GET request.

## HTTP hardening

- Security headers on every response: `X-Content-Type-Options`, `X-Frame-Options:
  DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, a restrictive API
  CSP (`default-src 'none'`), and HSTS in production.
- Caddy terminates TLS and adds the same headers for the SPA.

## Execution isolation

- The API process never runs arbitrary user-supplied code.
- Controlled task execution / exploit runner are **disabled by default** and
  require `ADCC_ENABLE_TASK_EXECUTION=1` plus a sandboxed runner. Until then the
  editor, library, downloads, and local utilities remain fully functional.
- The container runs as a non-root user; the Docker socket is **not** mounted.

## Network exposure

- Only the reverse proxy is published. The backend listens on an internal port
  (`expose`, not `ports`); the database is a file inside the data volume.
- Do not expose ingestion/admin ports publicly. Prefer a VPN-only deployment for
  the whole app where competition rules allow.

## Secrets

- `ADCC_SECRET_KEY` and the shared password are the only secrets; set via env /
  CLI, never in git. Deploy SSH keys live in a GitHub **environment** (see GITHUB.md).
- Captured secrets in evidence are preserved for authorized investigation but kept
  out of logs; apply retention (`ADCC_EVENT_RETENTION_DAYS`) to traffic and flags.

## Backup & recovery

- Back up the `adcc-data` volume (SQLite DB + uploads). Example:
  `docker run --rm -v adcc-data:/data -v "$PWD":/backup alpine tar czf /backup/adcc-$(date +%F).tgz /data`
- Restore by extracting into the volume before `docker compose up`.
- Ordinary deploys never recreate the volume, so operational data survives updates.

## Known limitations

- Shared account ⇒ individual attribution is best-effort (session labels only).
- Passive PCAP cannot reveal encrypted HTTPS bodies (see NETWORK.md).
- The analyzer is pattern-based: it flags patterns, not proven exploitability, and
  "no match" is not proof of safety.
- Built-in rate limiting is per-IP in SQLite; front it with the proxy for scale.
