#!/usr/bin/env bash
# Restore a data volume from a backup tarball. STOP the stack first.
#   docker compose -f docker-compose.offline.yml down
#   ./scripts/restore.sh adcc-backup-YYYYMMDD-HHMMSS.tgz [volume-name]
set -euo pipefail
BACKUP="${1:?usage: restore.sh <backup.tgz> [volume]}"
VOL="${2:-adcc-command-center_adcc-offline-data}"
docker volume create "$VOL" >/dev/null
docker run --rm -v "${VOL}:/data" -v "$(pwd):/backup:ro" alpine \
  sh -c "rm -rf /data/* && tar xzf /backup/${BACKUP} -C /data"
echo "restored ${BACKUP} -> volume ${VOL}. Start the stack again."
