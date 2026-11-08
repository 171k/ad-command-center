# Changelog

## [Unreleased]: Pwn Solver upgrade

- **Names the vulnerability** from imports + checksec: stack buffer overflow
  (ret2win / ret2system / ret2libc) or possible format string, with the reasoning.
- **Auto-estimates the overflow offset** by disassembling the vulnerable function
  with capstone (buffer slot + saved rbp). Verified 56 bytes on the test binaries.
- Collects everything the exploit needs: win/system/"/bin/sh" addresses, GOT, and
  ROP gadgets (ROPgadget, with a byte-signature fallback).
- **Generates a tailored pwntools script** with the offset and addresses filled in,
  plus a find_offset() to confirm the exact offset on your own box.
- New deps: pyelftools, capstone, ROPgadget (deterministic, read-only, no AI). The
  binary is parsed and disassembled, never executed. Endpoint `/api/pwn/cases/{id}/solve`.

## [Unreleased]: Defense project scan (zip)

- **Scan a whole service at once.** New Defense "Project (zip)" tab: upload a zip
  of the service source and the backend extracts it to a sandbox and statically
  analyzes every file (built-in rules + Semgrep). The source is NEVER executed.
- Safe extraction guards against zip-slip, zip bombs, symlinks and oversized
  members; `node_modules`, `vendor`, `.git` and binaries are skipped.
- Runs as a background job (`POST /api/defense/scan`, poll `/scan/{id}`); results
  are saved and grouped by file, worst first, with a severity filter. Each finding
  keeps its line, exploit, example payload and patch.

## [Unreleased]: Defense code review with Semgrep

- **Defense code review upgraded.** The Analyze tab now runs two deterministic
  engines together: the built-in curated rules and **Semgrep** (multi-language,
  bundled offline ruleset, no registry, no AI). Findings are merged and deduped.
- **File upload.** Analyze a pasted snippet or upload a source file
  (`/api/defense/analyze-file`); binary and empty files are rejected.
- **Exploit / payload / patch for every finding.** A CWE enrichment table
  (`analyzer/enrich.py`) gives each finding, including Semgrep's, the four
  answers: the vulnerable line, the possible exploit, an example payload and how
  to patch it.
- Backend image now installs Semgrep; it runs fully offline against
  `analyzer/semgrep_rules/`. No new runtime network dependency.

## [vNext]: Competition Readiness (branch: feat/vnext-competition), unreleased

Dedicated dev branch for iHack 2026. **Not deployed to production.** HTTPS, auth,
CI/CD, Tailscale, SSH and all existing workspaces are preserved and untouched.

### Added
- **Tool Repository (P1):** self-hosted, GitHub-free tool distribution. Curated
  catalog (16 tools, licenses/provenance/per-OS install), artifact upload with
  SHA-256, TLS-authenticated downloads with integrity headers, tamper detection
  and a single-file **offline bundle** export. New `adtools` CLI (online +
  fully-offline) for `list/search/info/verify/install/offline-export`.
- **Pwn Solver (P2):** upload ELF challenge binaries for static analysis: format/arch, **checksec** (NX/PIE/RELRO/canary/fortify/stripped), symbols,
  strings, sections. Deterministic utilities: De Bruijn **cyclic** + offset,
  arch-aware **pack/unpack**, **ROP gadget** search, **pwntools template**, saved
  exploit scripts and notes per case. Binaries are parsed, never executed by the
  web app; `scripts/pwn_sandbox.py` runs crash/exploit tests in an isolated LOCAL
  sandbox (non-root, no network, rlimits, timeouts). Server-side exec gated off.
- **Offline fallback (P3):** `docker-compose.offline.yml` (turnkey localhost,
  no external deps), `scripts/backup.sh` / `restore.sh` and `docs/OFFLINE.md`.
- **Audit (P4):** `docs/AUDIT.md`, evidence-based verified/partial/blocked review.

### Changed
- `config.py`: `tools_dir`, `pwn_dir`, artifact/binary size caps, `enable_pwn_exec`.
- Migrations 0003 (tools) + 0004 (pwn), additive; existing data untouched.
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

## [0.2.0]: Production (main)
- Per-user accounts (shared data); HTTPS at itikad.site; Tailscale auto-deploy;
  sandboxed local-utility runner; SOC clear-demo-data; dakimomo favicon.

## [0.1.0]: Initial
- Attack / Defense / Automation / Network-SOC workspaces; deterministic analyzer;
  SOC offense correlation + evidence-based outcomes; Docker/Caddy deploy; CI/CD.
