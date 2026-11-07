# Deployment

Target: a Linux VPS with ~4 GB RAM / 2 vCPU and Docker. The stack is two
containers — `backend` (FastAPI/uvicorn, internal) and `web` (Caddy serving the
SPA and reverse-proxying the API).

> Docker images were authored and their configs validated here, but **this build
> machine has no Docker**, so the images were not built on it. Build on the VPS
> (or any Docker host) with the commands below.

## 1. Prepare

```bash
git clone <your-private-repo> /opt/adcc-command-center
cd /opt/adcc-command-center
cp .env.example .env
```

Edit `.env`:

```ini
ADCC_ENVIRONMENT=production
ADCC_SECRET_KEY=<64+ random chars>      # openssl rand -base64 48
ADCC_COOKIE_SECURE=true
DOMAIN=ad.example.com                   # for automatic HTTPS; or ":80" for plain HTTP
```

Never commit `.env`.

## 2. Build & start

```bash
docker compose up -d --build
docker compose exec backend python -m app.admin set-password   # set the shared password
```

- `DOMAIN` set to a real hostname ⇒ Caddy obtains a Let's Encrypt certificate
  automatically (ports 80/443 must be reachable).
- `DOMAIN=:80` ⇒ plain HTTP for a local/VPN-only deployment (set
  `ADCC_COOKIE_SECURE=false` in that case).

## 3. Verify

```bash
curl -fsS https://ad.example.com/api/health      # {"status":"ok",...}
docker compose ps                                 # both services healthy
```

## 4. Persistence

Operational data lives in the `adcc-data` Docker volume (SQLite DB + uploads).
`docker compose up -d --build` rebuilds images **without** touching the volume, so
findings, offenses, scripts, settings, and uploads survive deploys. Schema changes
apply automatically via ordered migrations on startup (never a drop/recreate).

## 5. Backups

```bash
# Backup
docker run --rm -v adcc-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/adcc-$(date +%F).tgz /data
# Restore (stop stack first)
docker compose down
docker run --rm -v adcc-data:/data -v "$PWD":/backup alpine \
  sh -c "rm -rf /data/* && tar xzf /backup/adcc-YYYY-MM-DD.tgz -C /"
docker compose up -d
```

Schedule the backup via cron; store copies off-box.

## 6. Resource limits

`docker-compose.yml` caps the backend at 1.5 CPU / 1 GB and web at 0.5 CPU /
256 MB, and rotates container logs (10 MB × 3). Run heavy packet processing
(Suricata/Zeek/tshark on large captures) on a **separate** collector host.

## 7. Updates, rollback & CI/CD

- Manual update: `git pull && docker compose up -d --build`.
- Automated: `.github/workflows/deploy.yml` deploys over SSH after CI passes on
  `main`, with a health-gate and automatic `git reset` rollback on failure. See
  [GITHUB.md](GITHUB.md) for the required secrets.
- The app does not depend on GitHub at runtime — if GitHub is down mid-competition,
  the running stack is unaffected.

## 8. Local / offline deployment

Same compose works on a laptop with `DOMAIN=:80` and
`ADCC_COOKIE_SECURE=false`. No Internet, GitHub, or AI services are needed at
runtime. Transfer to an air-gapped machine by copying the repo and (optionally)
`docker save`/`docker load` of the built images; restore the data volume from a backup.
