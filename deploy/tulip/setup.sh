#!/usr/bin/env bash
# One-command Tulip setup for the A&D Command Center host.
#
#   cd ~/adcc-command-center && git pull && bash deploy/tulip/setup.sh
#
# Idempotent: safe to re-run. Clones/updates Tulip, applies the resource +
# toolchain fixes, starts it, and publishes it at https://tulip.itikad.site
# behind HTTP basic auth (user: team). Game-day values (tick length, flag regex,
# service list) are edited afterwards per deploy/tulip/README.md.
set -euo pipefail

ADCC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # ~/adcc-command-center
OVR="$ADCC/deploy/tulip/docker-compose.override.yml"
TULIP_DIR="${TULIP_DIR:-$HOME/tulip}"

echo "==> [1/5] clone / update Tulip"
if [ ! -d "$TULIP_DIR/.git" ]; then
  git clone --depth 1 https://github.com/OpenAttackDefenseTools/tulip.git "$TULIP_DIR"
fi
cd "$TULIP_DIR"

echo "==> [2/5] toolchain fix (timescale builds without clang-19)"
# The timescale image installs clang15 but PG expects clang-19; skip the optional
# LLVM JIT bitcode. The gcc-built extension Postgres actually loads is unaffected.
sed -i 's/make USE_PGXS=1 install/make USE_PGXS=1 with_llvm=no install/g' services/timescale/Dockerfile

echo "==> [3/5] config (full upstream .env; keep upstream configurations.py)"
# Use Tulip's complete .env (has TRAFFIC_DIR_DOCKER etc.). Do NOT overwrite
# services/api/configurations.py — webservice.py imports many names from it;
# edit it in place on game day for the real services.
[ -f .env ] || cp .env.example .env

echo "==> [4/5] build + start (resource-tuned for this VM)"
docker compose -f docker-compose.yml -f "$OVR" up -d --build

echo "==> [5/5] publish behind Caddy (validated before restart)"
cd "$ADCC"
docker compose cp "$ADCC/deploy/tulip/tulip.caddy.example" web:/etc/caddy/conf.d/tulip.caddy
if docker compose exec -T web caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
  docker compose restart web
else
  echo "!! Caddy config invalid — removing drop-in, not restarting" >&2
  docker compose exec -T web rm -f /etc/caddy/conf.d/tulip.caddy || true
  exit 1
fi

echo
echo "Tulip is up. https://tulip.itikad.site  (user: team)"
echo "Containers:"
cd "$TULIP_DIR"
docker compose -f docker-compose.yml -f "$OVR" ps --format "  {{.Name}}\t{{.Status}}"
