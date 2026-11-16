#!/usr/bin/env bash
# Fetch optional static x86_64 binaries into deploy/tulip/bin/ — run this ONCE
# before the game, while you still have internet. capture-setup.sh will then scp
# them to a bare/air-gapped vulnbox that lacks the tools.
#
#   bash deploy/tulip/fetch-static-bins.sh
#
# socat-x86_64 is already vendored in the repo. This adds the static python2.7
# fallback (15 MB) for the rare vulnbox with no python3 at all. All verified by
# SHA256. Source: github.com/andrew-d/static-binaries (musl, static).
set -euo pipefail
BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/bin"
mkdir -p "$BIN"; cd "$BIN"
BASE="https://raw.githubusercontent.com/andrew-d/static-binaries/master/binaries/linux/x86_64"

fetch() {  # <dst> <src-name> <sha256>
  if [ -f "$1" ] && echo "$3  $1" | sha256sum -c - >/dev/null 2>&1; then
    echo "ok (cached): $1"; return; fi
  echo "fetching $1…"
  curl -fsSL -m 180 "$BASE/$2" -o "$1"
  echo "$3  $1" | sha256sum -c - || { echo "CHECKSUM MISMATCH for $1 — deleting" >&2; rm -f "$1"; exit 1; }
  chmod +x "$1"
}

fetch socat-x86_64     socat      71c81cb46dd1903f12f3aef844b0fc559f31e2f613a8ae91ffb5630bc7011ef5
fetch python2.7-x86_64 python2.7  7380f2014a705e6b4cf0ab7614a1eea440cf7eab6093767921aa881a4219818b

echo "done:"; ls -la "$BIN"
