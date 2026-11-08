# Offline / air-gapped operation

The Command Center is designed to run with **no GitHub, Azure, external API, CDN,
or AI service** at runtime. This guide covers running it entirely locally for the
competition (Windows 11 + WSL2/Docker, or any Linux with Docker).

## What works offline

| Capability | Offline? |
|---|---|
| Login / per-user auth | ✅ local (SQLite) |
| Attack, Defense, Automation, Network/SOC, Pwn Solver | ✅ (no external calls at runtime) |
| Tool Repository + `adtools` install | ✅ from the hosted artifacts / offline bundle |
| Deterministic analysis (code rules, checksec, cyclic/pack, utilities) | ✅ |
| Live cross-session sync (SSE) | ✅ (local) |
| Recon / service health | ✅ against hosts reachable on your LAN |
| HTTPS with a public cert | ❌ needs internet for ACME — use plain HTTP locally |
| GitHub auto-deploy | ❌ not needed offline; update by rebuilding locally |

Fonts: the UI links Google Fonts when online but **falls back to system fonts**
offline — no external font is *required*.

## Prerequisites (one-time, while you still have internet)

1. Install Docker Desktop (Windows) or Docker Engine (Linux). On Windows enable
   the WSL2 backend.
2. Copy this repository to the machine (USB/zip is fine — no `git` needed).
3. Pre-build the images so no pulls are needed later:
   ```bash
   docker compose -f docker-compose.offline.yml build
   ```
4. (Optional) `docker save` the built images to a file to move them to an
   air-gapped box: `docker save adcc-command-center-backend adcc-command-center-web -o adcc-images.tar`
   then `docker load -i adcc-images.tar` on the target.
5. Download the **offline tool bundle** from a running instance (Tool Repository →
   *Offline bundle*, or `adtools offline-export`) and keep it with the repo.

## Start it (offline)

```bash
docker compose -f docker-compose.offline.yml up -d --build
```
```bash
# first run only — create the team accounts
docker compose -f docker-compose.offline.yml exec backend python -m app.admin seed-users --default "<a-strong-password>"
```

Open **http://localhost:8080** and sign in. Change `OFFLINE_PORT` in the env to
use a different port. Set a real `ADCC_SECRET_KEY` for anything beyond a laptop.

## Tools without GitHub

```bash
python3 adtools.py --offline --bundle ./adcc-tool-bundle install ffuf
python3 adtools.py --offline --bundle ./adcc-tool-bundle verify pwntools
```
Every artifact is SHA-256 verified against the bundle manifest before use.

## Backup & restore (portable)

The entire state (DB, uploads, tool artifacts, pwn binaries) lives in one Docker
volume. Back it up and carry it on a USB stick:

```bash
./scripts/backup.sh adcc-command-center_adcc-offline-data
```
Restore (stop the stack first):
```bash
docker compose -f docker-compose.offline.yml down
./scripts/restore.sh adcc-backup-YYYYMMDD-HHMMSS.tgz adcc-command-center_adcc-offline-data
docker compose -f docker-compose.offline.yml up -d
```

Per-feature portable exports also exist: SOC event export, the tool bundle, and
saved pwntools scripts (copy/download from the UI).

## Verify it is truly offline

1. Start the stack, sign in, create a finding, upload a binary — confirm they work.
2. **Disconnect the network** (airplane mode / `docker network disconnect`, or pull
   the cable).
3. `docker compose -f docker-compose.offline.yml restart`.
4. Reload http://localhost:8080 — login, findings, SOC, Pwn, and the tool bundle
   all still work; your records survived the restart.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Port 8080 in use | set `OFFLINE_PORT=9090` and re-up |
| `seed-users` says accounts exist | they're already created; just log in |
| Can't reach the site | `docker compose -f docker-compose.offline.yml ps` — both services `Up`? check `logs` |
| PCAP upload disabled | `tshark` is in the image; if you built with `INSTALL_TSHARK=false`, rebuild |
| Lost data after `down -v` | `-v` deletes volumes — never use it; restore from backup |
