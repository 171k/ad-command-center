# Changelog

## [Unreleased]: A&D operations upgrade (branch feat/ad-ops-upgrade, not deployed)

Research-driven upgrade for iHack 2026 (see docs/RESEARCH-iHack2026.md). Deterministic,
offline, no runtime AI. Nothing runs untrusted code on the server.

### Added
- **RCE Script Generator** (Attack -> RCE Gen): turns a verified vulnerability into a
  reusable, editable Python script (requests / raw HTTP / TCP / pwntools), with export.
  Generation only, never executed here. The target must be a **registered authorised
  service** (enforced server-side; unauthorised hosts get 403).
- **tcpdump capture wizard** (SOC -> Capture & IR): builds a bounded, rotated capture
  command (and a rotate-and-upload variant) from interface/port/filter inputs.
- **Operational guides** (searchable, copyable parameterized commands, warnings):
  packet capture, Linux persistence reference, persistence investigation/removal,
  Docker operations (pull/build/tag/push/save/load), and container recovery. In SOC
  (Capture & IR) and Defense (Playbooks).
- New `ops` module + `/api/ops/*` endpoints (`generators.py`, `guides.py`); tests in
  `test_ops.py` (generated scripts parse, scope 403, tcpdump bounded + injection-safe).

### Deferred / needs more work (honest status)
- Attack Jobs execution engine (bounded sequential runs of operator scripts) is scoped
  but not built; execution would stay in the gated sandbox worker. Management/allowlist/
  emergency-stop UI pending.
- Defense patch view already shows vulnerable code -> explanation -> patch -> regression
  test; the unified before/after diff and patch-history/status tracking are not yet added.
- Optional pkappa2 sidecar is referenced in the guide, not integrated (no stable API).

## [Unreleased]: Semgrep community ruleset for project scans

- **Much broader vulnerability detection.** The Defense project (zip) scan now
  runs the built-in rules PLUS the full official **Semgrep community ruleset**
  (~1,900 rules across EVERY supported language, not just the common web ones),
  vendored into the image (pinned commit) so it stays fully offline.
- Added CTF/attack-defense custom rules (`ctf.yml`): PHP LFI, type-juggling auth,
  `preg_replace /e`, JWT verification disabled, hardcoded-backdoor comparisons.
- Overlapping findings are deduped by line + CWE; CWE still drives the
  exploit/payload/patch enrichment. If a community rule misbehaves, the scan
  falls back to the built-in rules so it never comes back empty.
- The interactive single-file Analyze stays on the fast built-in rules; the
  heavier community pass runs in the background project scan where latency is fine.
- Note: static pattern matching cannot find logic/auth/business-logic bugs. A
  clean scan still does not prove the code is secure.

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
