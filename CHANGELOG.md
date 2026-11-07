# Changelog

## [vNext] — Competition Readiness (branch: feat/vnext-competition) — unreleased

Dedicated dev branch for iHack 2026. **Not deployed to production.** HTTPS, auth,
CI/CD, Tailscale, SSH and all existing workspaces are preserved and untouched.

### Added
- **Tool Repository (P1):** self-hosted, GitHub-free tool distribution. Curated
  catalog (16 tools, licenses/provenance/per-OS install), artifact upload with
  SHA-256, TLS-authenticated downloads with integrity headers, tamper detection,
  and a single-file **offline bundle** export. New `adtools` CLI (online +
  fully-offline) for `list/search/info/verify/install/offline-export`.
- **Pwn Solver (P2):** upload ELF challenge binaries for static analysis —
  format/arch, **checksec** (NX/PIE/RELRO/canary/fortify/stripped), symbols,
  strings, sections. Deterministic utilities: De Bruijn **cyclic** + offset,
  arch-aware **pack/unpack**, **ROP gadget** search, **pwntools template**, saved
  exploit scripts and notes per case. Binaries are parsed, never executed by the
  web app; `scripts/pwn_sandbox.py` runs crash/exploit tests in an isolated LOCAL
  sandbox (non-root, no network, rlimits, timeouts). Server-side exec gated off.
- **Offline fallback (P3):** `docker-compose.offline.yml` (turnkey localhost,
  no external deps), `scripts/backup.sh` / `restore.sh`, and `docs/OFFLINE.md`.
- **Audit (P4):** `docs/AUDIT.md` — evidence-based verified/partial/blocked review.

### Changed
- `config.py`: `tools_dir`, `pwn_dir`, artifact/binary size caps, `enable_pwn_exec`.
- Migrations 0003 (tools) + 0004 (pwn) — additive; existing data untouched.
- Navigation: added **Pwn Solver** workspace and **Tool Repository** (Shared).

### Tests
- +11 tests (tools ×4, pwn ×7). 59 backend tests pass; frontend builds; lint clean.

### Notes / limitations
- Flag auto-submission, scheduled jobs, server-side binary execution remain gated
  off pending organizer approval / a configured sandbox.
- Hosted tool *binaries* are uploaded by an admin during prep (license-reviewed);
  the catalog ships metadata + the upload/verify/offline mechanism.
- No optimistic locking on concurrent edits of the same record (last-write-wins).

---

## [0.2.0] — Production (main)
- Per-user accounts (shared data); HTTPS at itikad.site; Tailscale auto-deploy;
  sandboxed local-utility runner; SOC clear-demo-data; dakimomo favicon.

## [0.1.0] — Initial
- Attack / Defense / Automation / Network-SOC workspaces; deterministic analyzer;
  SOC offense correlation + evidence-based outcomes; Docker/Caddy deploy; CI/CD.
