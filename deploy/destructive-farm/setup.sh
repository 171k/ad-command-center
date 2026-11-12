#!/usr/bin/env bash
# One-command Destructive Farm setup for the A&D Command Center host.
#
#   cd ~/adcc-command-center && git pull && bash deploy/destructive-farm/setup.sh
#
# Idempotent. Clones Destructive Farm, adds the Docker build (upstream ships
# none), sets the login password, starts it, and publishes it at
# https://df.itikad.site. The farm config (teams, flag format, submit protocol)
# is edited on game day per deploy/destructive-farm/README.md.
set -euo pipefail

ADCC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # ~/adcc-command-center
HERE="$ADCC/deploy/destructive-farm"
DF_DIR="${DF_DIR:-$HOME/destructive-farm}"
# Login password (HTTP basic auth, any username). Override: DF_PW=... bash setup.sh
DF_PW="${DF_PW:-lastpaksajihadf}"

echo "==> [1/4] clone / update Destructive Farm"
if [ ! -d "$DF_DIR/.git" ]; then
  git clone --depth 1 https://github.com/DestructiveVoice/DestructiveFarm.git "$DF_DIR"
fi
cd "$DF_DIR"

echo "==> [2/4] add Docker build + set login password"
cp "$HERE/Dockerfile" server/Dockerfile
cp "$HERE/docker-compose.yml" docker-compose.yml
sed -i "s/'SERVER_PASSWORD': *'[^']*'/'SERVER_PASSWORD': '$DF_PW'/" server/config.py

echo "==> [3/4] build + start"
docker compose up -d --build

echo "==> [4/4] publish behind Caddy (validated before restart)"
cd "$ADCC"
docker compose cp "$HERE/df.caddy.example" web:/etc/caddy/conf.d/df.caddy
if docker compose exec -T web caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
  docker compose restart web
else
  echo "!! Caddy config invalid — removing drop-in, not restarting" >&2
  docker compose exec -T web rm -f /etc/caddy/conf.d/df.caddy || true
  exit 1
fi

echo
echo "Destructive Farm is up. https://df.itikad.site"
echo "Login: any username + the farm password."
docker compose -f "$DF_DIR/docker-compose.yml" ps --format "  {{.Name}}\t{{.Status}}" 2>/dev/null || true
