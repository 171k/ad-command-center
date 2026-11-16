#!/usr/bin/env bash
# Set up live traffic capture on YOUR vulnbox and link it into Tulip via
# PCAP-over-IP. Run this on the machine where your (local) Tulip is running, on
# the competition network — Tulip must be able to reach the vulnbox.
#
#   bash deploy/tulip/capture-setup.sh
#
# It will ask for the vulnbox IP and SSH password, start a tcpdump->socat broker
# on the vulnbox (filtered to your service ports, SSH excluded), then set
# PCAP_OVER_IP in Tulip's .env and restart Tulip's assembler so packets stream
# straight in. Re-runnable.
#
# Credentials: you type the vulnbox password at the prompt; it is used only for
# this run (passed to ssh via the SSHPASS env var, never written to disk).
set -euo pipefail

ADCC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OVR="$ADCC/deploy/tulip/docker-compose.override.yml"
TULIP_DIR="${TULIP_DIR:-$HOME/tulip}"

ask() { local p="$1" d="${2:-}" v; read -r -p "$p${d:+ [$d]}: " v; echo "${v:-$d}"; }

echo "=== Tulip capture setup (PCAP-over-IP) ==="
VULN_IP="$(ask 'Vulnbox IP')"
SSH_USER="$(ask 'Vulnbox SSH user' root)"
SSH_PORT="$(ask 'Vulnbox SSH port' 22)"
read -r -s -p "Vulnbox SSH password: " SSH_PW; echo
IFACE="$(ask 'Capture interface on the vulnbox' eth0)"
PORTS="$(ask 'Service ports to capture (space/comma separated, blank = all)' '')"
BROKER_PORT="$(ask 'Broker port on the vulnbox' 1337)"

[ -n "$VULN_IP" ] || { echo "vulnbox IP is required" >&2; exit 1; }

# Build a BPF: the given ports (any), always excluding SSH and the broker port.
BPF="not port $SSH_PORT and not port $BROKER_PORT"
if [ -n "$PORTS" ]; then
  ORS=""; P=""
  for p in ${PORTS//,/ }; do case "$p" in (*[!0-9]*|'') ;; (*) P="$P$ORS port $p"; ORS=" or ";; esac; done
  [ -n "$P" ] && BPF="($P) and $BPF"
fi
echo "BPF filter: $BPF"

command -v sshpass >/dev/null 2>&1 || {
  echo "Installing sshpass (needs sudo)…"; sudo apt-get update -qq && sudo apt-get install -y -qq sshpass; }

SSH="sshpass -e ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p $SSH_PORT $SSH_USER@$VULN_IP"

echo "=== [1/3] preparing the vulnbox ($VULN_IP) ==="
# A wrapper script on the vulnbox avoids socat EXEC quoting issues with the BPF.
export SSHPASS="$SSH_PW"
$SSH "bash -s" <<REMOTE
set -e
export DEBIAN_FRONTEND=noninteractive
need() { command -v "\$1" >/dev/null 2>&1; }
if ! need tcpdump || ! need socat; then
  (sudo apt-get update -qq && sudo apt-get install -y -qq tcpdump socat) || \
  (apt-get update -qq && apt-get install -y -qq tcpdump socat)
fi
# Per-connection fresh tcpdump -> clean PCAP-over-IP stream for each client.
cat > /tmp/tulip-capture.sh <<WRAP
#!/bin/sh
exec tcpdump -i $IFACE -w - -U -n -s 0 $BPF
WRAP
chmod +x /tmp/tulip-capture.sh
# Stop any previous broker, start a new detached one.
pkill -f "TCP-LISTEN:$BROKER_PORT" 2>/dev/null || true
sleep 1
setsid socat TCP-LISTEN:$BROKER_PORT,fork,reuseaddr EXEC:/tmp/tulip-capture.sh >/tmp/tulip-capture.log 2>&1 < /dev/null &
sleep 1
if pgrep -f "TCP-LISTEN:$BROKER_PORT" >/dev/null; then echo "broker listening on $BROKER_PORT ($IFACE)"; else echo "BROKER FAILED; see /tmp/tulip-capture.log"; exit 1; fi
REMOTE

echo "=== [2/3] pointing Tulip at $VULN_IP:$BROKER_PORT ==="
if [ ! -d "$TULIP_DIR" ]; then
  echo "Tulip not found at $TULIP_DIR. Set PCAP_OVER_IP=\"$VULN_IP:$BROKER_PORT\" in Tulip's .env and restart its assembler."
  exit 0
fi
ENV="$TULIP_DIR/.env"
touch "$ENV"
# host.docker.internal lets the assembler container reach the host's network;
# the broker is on the vulnbox, reachable directly by IP from the host.
if grep -q '^PCAP_OVER_IP=' "$ENV"; then
  sed -i "s|^PCAP_OVER_IP=.*|PCAP_OVER_IP=\"$VULN_IP:$BROKER_PORT\"|" "$ENV"
else
  echo "PCAP_OVER_IP=\"$VULN_IP:$BROKER_PORT\"" >> "$ENV"
fi
grep '^PCAP_OVER_IP=' "$ENV"

echo "=== [3/3] restarting Tulip assembler ==="
cd "$TULIP_DIR"
docker compose -f docker-compose.yml -f "$OVR" up -d assembler
sleep 4
echo "--- assembler log (should show flows arriving once there is traffic) ---"
docker logs --tail 6 tulip-assembler-1 2>&1 || true

cat <<EOF

================ CAPTURE LINKED ================
Vulnbox broker : $VULN_IP:$BROKER_PORT   (interface $IFACE)
Tulip ingest   : PCAP-over-IP -> $TULIP_DIR/.env

Open Tulip and watch flows appear. If none show:
  - confirm Tulip can reach the vulnbox:  nc -vz $VULN_IP $BROKER_PORT
  - check the broker on the vulnbox:      /tmp/tulip-capture.log
  - make sure the BPF matches real service ports.
The broker is a detached process; re-run this script after a vulnbox reboot.
===============================================
EOF
