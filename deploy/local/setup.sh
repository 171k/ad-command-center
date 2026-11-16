#!/usr/bin/env bash
# One-command LOCAL setup for the whole A&D stack on THIS machine (plain HTTP on
# localhost — a laptop, or a box on the competition LAN). Brings up:
#   - Command Center app  -> http://localhost:8080
#   - Tulip               -> http://localhost:3000
#   - Destructive Farm    -> http://localhost:5000
#   - the Tulip control agent (so the in-app "Save & Rebuild" works locally)
#
# Usage:
#   git clone https://github.com/171k/ad-command-center.git
#   cd ad-command-center
#   bash deploy/local/setup.sh
#
# Options (env):  APP_PW=<min10>  DF_PW=<pw>  bash deploy/local/setup.sh
# Requirements: docker (with compose v2), git, python3, bash. Idempotent.
set -euo pipefail

ADCC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ADCC"
APP_PW="${APP_PW:-changeme-local}"          # >= 10 chars (seed-users requirement)
export ADCC_LOCAL=1                          # tool setup scripts skip the TLS/Caddy publish
export DF_PW="${DF_PW:-lastpaksajihadf}"

for t in docker git python3; do
  command -v "$t" >/dev/null 2>&1 || { echo "ERROR: '$t' is required but not installed." >&2; exit 1; }
done
docker compose version >/dev/null 2>&1 || { echo "ERROR: docker compose v2 is required." >&2; exit 1; }
if [ "${#APP_PW}" -lt 10 ]; then echo "ERROR: APP_PW must be at least 10 characters." >&2; exit 1; fi

OFFLINE="docker compose -f docker-compose.offline.yml"

echo "######## [1/4] Command Center (offline) ########"
mkdir -p control && { chmod 777 control 2>/dev/null || true; }
$OFFLINE up -d --build
echo "   waiting for the app to come up…"
for i in $(seq 1 25); do
  if $OFFLINE exec -T backend curl -fsS http://127.0.0.1:8000/api/health >/dev/null 2>&1; then break; fi
  sleep 3
done
$OFFLINE exec -T backend python -m app.admin seed-users --default "$APP_PW" </dev/null || \
  echo "   (user seeding skipped/failed — set a password with: $OFFLINE exec backend python -m app.admin seed-users --default '<pw>')"

echo "######## [2/4] Tulip ########"
bash "$ADCC/deploy/tulip/setup.sh"

echo "######## [3/4] Destructive Farm ########"
bash "$ADCC/deploy/destructive-farm/setup.sh"

echo "######## [4/4] Tulip control agent (for Save & Rebuild) ########"
bash "$ADCC/deploy/tulip/agent-setup.sh" || \
  echo "   (agent setup had issues; start it manually: nohup python3 deploy/tulip/control-agent.py >> control/agent.log 2>&1 &)"

cat <<EOF

================= LOCAL STACK IS UP =================
  Command Center  : http://localhost:8080
      users: itik mejik gha namia   password: $APP_PW   (itik is admin)
  Tulip           : http://localhost:3000
  Destructive Farm: http://localhost:5000   (any username / $DF_PW)

  Configure Tulip from the app: Network/SOC -> Tulip tab -> fill in -> Save & Rebuild.
  Configure Destructive Farm on game day: ~/destructive-farm/server/config.py.

  Everything runs on this machine over plain HTTP (no TLS, no public domain).
  Keep this host off the public internet; it is meant for localhost / the game LAN.
====================================================
EOF
