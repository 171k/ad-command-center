#!/usr/bin/env bash
# Back up the A&D Command Center data volume (DB + uploads + tools + pwn binaries).
# Works for any of the compose files; pass the volume name as $1 (default: offline).
set -euo pipefail
VOL="${1:-adcc-command-center_adcc-offline-data}"
OUT="${2:-adcc-backup-$(date +%Y%m%d-%H%M%S).tgz}"
docker run --rm -v "${VOL}:/data:ro" -v "$(pwd):/backup" alpine \
  tar czf "/backup/${OUT}" -C /data .
echo "backup written: ${OUT}  (volume ${VOL})"
