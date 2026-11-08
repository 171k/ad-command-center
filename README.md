# A&D Command Center

A private, self-hosted operations center for a four-person **Attack & Defense CTF**
team. It centralizes offensive references, deterministic defensive code analysis,
reusable automation and a beginner-friendly **mini-SIEM** with offense correlation
and evidence-based attack-outcome classification.

> **No runtime AI.** Detection and analysis use deterministic rules, curated
> signatures, traditional parsers and a correlation engine, never an LLM.
> The core application runs fully offline.

---

## What it does

Four workspaces behind **one shared team account** (four concurrent sessions,
optional "Player 1…Substitute" labels for attribution, not strong identity):

- **Attack**: authorized target registry (scope allowlist), bounded recon
  (TCP / banner / HTTP fingerprint), exploit-technique knowledge base and a
  flag utility with dedup + a configurable (off-by-default) submission adapter.
- **Defense**: paste code, get a structured analysis from a curated multi-language
  rule engine (optionally backed by local Semgrep). Each finding shows matched
  lines, why it's dangerous, a safe test, a language-specific patch, a regression
  test, references and honest limitations. "No match" never means "secure."
- **Automation**: script library with revisions/download, deterministic utilities
  (base64 / URL / hex / hashes / JWT-decode-no-verify / JSON / timestamp) and real
  service health checks. Controlled execution is gated off by default.
- **Network / SOC**: EVE/access-log/PCAP ingestion → **offense correlation** that
  groups thousands of automated attempts into single offenses, with **CONFIRMED /
  POSSIBLE / ATTEMPTED / BLOCKED** outcomes backed by transparent evidence, a
  payload inspector (raw / URL-decoded / hex), an event explorer, sensors and
  copy-pasteable setup guides (tcpdump, Suricata, TShark, Zeek, Tulip).

Shared **Findings** sync live across sessions (Server-Sent Events).

## Technology

| Layer     | Choice |
|-----------|--------|
| Frontend  | React 18 · TypeScript · Vite · Tailwind · TanStack Query (bundle ≈ 88 KB gzip) |
| Backend   | Python 3.12 · FastAPI · Pydantic · SQLite (WAL) · Argon2id |
| Analysis  | Deterministic rule engine (built-in) + optional local Semgrep |
| SOC feeds | Suricata EVE JSON · structured access logs · PCAP via TShark |
| Deploy    | Docker Compose · Caddy reverse proxy (auto-HTTPS) |

Reused upstream tools and their licenses are listed in [docs/THIRD_PARTY.md](docs/THIRD_PARTY.md).

## Requirements

- Backend: Python 3.11+ (3.12 recommended). Frontend: Node 20+ (22 recommended).
- Optional: `semgrep` (richer code rules), `tshark` (PCAP parsing), a Suricata
  sensor (live traffic). All optional pieces degrade gracefully when absent.
- Target VPS: ~4 GB RAM / 2 vCPU, Docker.

## Local development

```bash
# 1. Backend
cd backend
python -m venv .venv
.venv/Scripts/activate            # Windows;  source .venv/bin/activate on Linux/macOS
pip install -r requirements-dev.txt
python -m app.admin set-password  # one-time: set the shared team password
uvicorn app.main:app --reload --port 8000
```

```bash
# 2. Frontend (separate terminal): proxies /api to the backend on :8000
cd frontend
npm install
npm run dev                       # http://localhost:5173
```

Open http://localhost:5173, sign in with the password you set, pick a session label.

Optional demo data (clearly labeled as DEMO) to explore the SOC:

```bash
cd backend && python -m app.admin demo-data
```

## Tests

```bash
cd backend && pytest -q           # 40 tests: auth, analyzer, SOC correlation, API
cd frontend && npm run build      # type-check + production build
```

## Basic operations

```bash
python -m app.admin status                 # account + data counts
python -m app.admin set-password           # rotate the shared password
python -m app.admin seed-library           # load the curated script library
python -m app.admin create-sensor edge-1   # register a sensor, prints a one-time token
```

## Deployment & more

- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md): Docker Compose, HTTPS, backups, rollback.
- [docs/SECURITY.md](docs/SECURITY.md): threat model, secrets, isolation, exposure.
- [docs/SIEM.md](docs/SIEM.md): detection, correlation, outcome evidence rules.
- [docs/NETWORK.md](docs/NETWORK.md): sensors, PCAP, TLS visibility limits.
- [docs/GITHUB.md](docs/GITHUB.md): private repo, branches, PRs, CI/CD secrets.
- [docs/THIRD_PARTY.md](docs/THIRD_PARTY.md): reused tools, licenses, versions.

## Common troubleshooting

| Symptom | Fix |
|---|---|
| `Account not configured` on login | Run `python -m app.admin set-password`. |
| 403 on actions | CSRF cookie missing, ensure the frontend is same-origin (dev proxy or Caddy). |
| SOC dashboard empty | Ingest EVE/PCAP, register a sensor or load demo data. |
| PCAP upload disabled | Install `tshark`; EVE/access-log ingestion still work. |
| Semgrep note "not installed" | Built-in rules still run; install `semgrep` for more coverage. |

## Status at a glance

- **Implemented & tested:** auth, all four workspaces, analyzer, SOC correlation
  & classification, findings, utilities, service health, PCAP magic-validation,
  live sync; 40 backend tests + frontend build.
- **Implemented, awaiting external config:** flag-submission adapter (needs the
  organizer's API), live Suricata/Tulip sensors (need a collector host),
  CI/CD deploy (needs a VPS + SSH secrets), HTTPS (needs a domain).
- **Gated off by default:** controlled task execution / exploit runner (require a
  sandboxed runner and explicit opt-in).

See each doc for exact external steps. No production feature is faked.
