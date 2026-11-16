#!/usr/bin/env bash
# Set up live traffic capture on YOUR vulnbox and link it into Tulip via
# PCAP-over-IP. Run this where your (local) Tulip is, on the competition network
# — Tulip must be able to reach the vulnbox.
#
#   bash deploy/tulip/capture-setup.sh
#
# Asks for the vulnbox IP + SSH password, starts a capture broker on the vulnbox,
# then sets PCAP_OVER_IP in Tulip's .env and restarts Tulip's assembler so
# packets stream straight in. Re-runnable.
#
# Capture backend (auto-selected): tcpdump+socat if present/installable, else a
# zero-dependency Python sniffer we scp over (needs only python3 + root on the
# vulnbox — works on an air-gapped box with no tcpdump).
#
# Credentials: you type the vulnbox password at the prompt; it is used only for
# this run (passed to ssh/scp via SSHPASS, never written to disk).
set -euo pipefail

ADCC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ADCC/deploy/tulip"
OVR="$HERE/docker-compose.override.yml"
TULIP_DIR="${TULIP_DIR:-$HOME/tulip}"

ask() { local p="$1" d="${2:-}" v; read -r -p "$p${d:+ [$d]}: " v; echo "${v:-$d}"; }

echo "=== Tulip capture setup (PCAP-over-IP) ==="
VULN_IP="$(ask 'Vulnbox IP')"
SSH_USER="$(ask 'Vulnbox SSH user' root)"
SSH_PORT="$(ask 'Vulnbox SSH port' 22)"
read -r -s -p "Vulnbox SSH password: " SSH_PW; echo
IFACE="$(ask 'Capture interface (eth0, or "any" for the whole box)' any)"
PORTS="$(ask 'Service ports to capture (space/comma separated, blank = ALL)' '')"
BROKER_PORT="$(ask 'Broker port on the vulnbox' 1337)"
ALLOW_IP="$(ask 'Restrict broker to this Tulip host IP (blank = allow any; NOT recommended)' '')"
[ -n "$VULN_IP" ] || { echo "vulnbox IP is required" >&2; exit 1; }

# Port filter in both forms: a tcpdump BPF string, and --include/--exclude args
# for the Python sniffer. SSH + the broker port are always excluded.
BPF="not port $SSH_PORT and not port $BROKER_PORT"
EXCL_ARGS="--exclude-port $SSH_PORT --exclude-port $BROKER_PORT"
INCL_ARGS=""
if [ -n "$PORTS" ]; then
  P=""; ORS=""
  for p in ${PORTS//,/ }; do
    case "$p" in (*[!0-9]*|'') ;; (*) P="$P$ORS port $p"; ORS=" or "; INCL_ARGS="$INCL_ARGS --include-port $p";; esac
  done
  [ -n "$P" ] && BPF="($P) and $BPF"
fi
echo "Filter: ${PORTS:-ALL traffic} on iface ${IFACE}  (SSH + broker port excluded)"

command -v sshpass >/dev/null 2>&1 || {
  echo "Installing sshpass locally (needs sudo)…"; sudo apt-get update -qq && sudo apt-get install -y -qq sshpass; }
export SSHPASS="$SSH_PW"
SSHO="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
SSH="sshpass -e ssh $SSHO -p $SSH_PORT $SSH_USER@$VULN_IP"
SCP="sshpass -e scp $SSHO -P $SSH_PORT"

echo "=== [1/3] probing the vulnbox ($VULN_IP) ==="
AVAIL="$($SSH 'for t in tcpdump socat python3 apt-get; do command -v $t >/dev/null 2>&1 && echo $t; done' || true)"
has() { printf '%s\n' "$AVAIL" | grep -qx "$1"; }
echo "  available: $(printf '%s ' $AVAIL)"

if { ! has tcpdump || ! has socat; } && has apt-get; then
  echo "  trying to install tcpdump+socat via apt (needs internet on the vulnbox)…"
  $SSH 'export DEBIAN_FRONTEND=noninteractive; (sudo apt-get update -qq && sudo apt-get install -y -qq tcpdump socat) || (apt-get update -qq && apt-get install -y -qq tcpdump socat)' >/dev/null 2>&1 || true
  AVAIL="$($SSH 'for t in tcpdump socat python3; do command -v $t >/dev/null 2>&1 && echo $t; done' || true)"
fi

echo "=== [2/3] starting the capture broker ==="
RANGE=""; [ -n "$ALLOW_IP" ] && RANGE=",range=$ALLOW_IP/32"
if has tcpdump && has socat; then
  MODE="tcpdump + socat"
  export IFACE BPF BROKER_PORT RANGE
  $SSH "IFACE='$IFACE' BPF='$BPF' BROKER_PORT='$BROKER_PORT' RANGE='$RANGE' bash -s" <<'REMOTE'
set -e
SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo"
cat > /tmp/tulip-capture.sh <<WRAP
#!/bin/sh
exec $SUDO tcpdump -i "$IFACE" -w - -U -n -s 0 "$BPF"
WRAP
chmod +x /tmp/tulip-capture.sh
pkill -f "TCP-LISTEN:$BROKER_PORT" 2>/dev/null || true; sleep 1
setsid socat "TCP-LISTEN:$BROKER_PORT,fork,reuseaddr$RANGE" EXEC:/tmp/tulip-capture.sh >/tmp/tulip-capture.log 2>&1 < /dev/null &
sleep 1
pgrep -f "TCP-LISTEN:$BROKER_PORT" >/dev/null && echo "broker up ($BROKER_PORT)" || { echo FAILED; cat /tmp/tulip-capture.log; exit 1; }
REMOTE
elif has python3; then
  MODE="python3 sniffer (no tcpdump needed)"
  echo "  tcpdump/socat unavailable — shipping the zero-dependency Python sniffer"
  $SCP "$HERE/pcap-over-ip.py" "$SSH_USER@$VULN_IP:/tmp/pcap-over-ip.py" >/dev/null
  ALLOW_ARG=""; [ -n "$ALLOW_IP" ] && ALLOW_ARG="--allow-ip $ALLOW_IP"
  $SSH "IFACE='$IFACE' BROKER_PORT='$BROKER_PORT' ARGS='$EXCL_ARGS $INCL_ARGS $ALLOW_ARG' bash -s" <<'REMOTE'
set -e
SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo"
pkill -f pcap-over-ip.py 2>/dev/null || true; sleep 1
setsid $SUDO python3 /tmp/pcap-over-ip.py --port $BROKER_PORT --iface $IFACE $ARGS >/tmp/tulip-capture.log 2>&1 < /dev/null &
sleep 2
pgrep -f pcap-over-ip.py >/dev/null && echo "python broker up ($BROKER_PORT)" || { echo FAILED; cat /tmp/tulip-capture.log; exit 1; }
REMOTE
else
  echo "ERROR: vulnbox has no tcpdump/socat and no python3, and no apt to install." >&2
  echo "Fix: briefly give it internet (apt-get install tcpdump socat), or scp a STATIC" >&2
  echo "tcpdump binary and run it manually (see deploy/tulip/README.md)." >&2
  exit 1
fi
echo "  capture backend: $MODE"

echo "=== [3/3] pointing Tulip at $VULN_IP:$BROKER_PORT ==="
if [ ! -d "$TULIP_DIR" ]; then
  echo "Tulip not found at $TULIP_DIR — set PCAP_OVER_IP=\"$VULN_IP:$BROKER_PORT\" in its .env and restart the assembler."
  exit 0
fi
ENV="$TULIP_DIR/.env"; touch "$ENV"
if grep -q '^PCAP_OVER_IP=' "$ENV"; then
  sed -i "s|^PCAP_OVER_IP=.*|PCAP_OVER_IP=\"$VULN_IP:$BROKER_PORT\"|" "$ENV"
else
  echo "PCAP_OVER_IP=\"$VULN_IP:$BROKER_PORT\"" >> "$ENV"
fi
grep '^PCAP_OVER_IP=' "$ENV"
cd "$TULIP_DIR"
docker compose -f docker-compose.yml -f "$OVR" up -d assembler
sleep 4
echo "--- assembler log ---"; docker logs --tail 6 tulip-assembler-1 2>&1 || true

cat <<EOF

================ CAPTURE LINKED ($MODE) ================
Vulnbox broker : $VULN_IP:$BROKER_PORT   (interface $IFACE)${ALLOW_IP:+, restricted to $ALLOW_IP}
Tulip ingest   : PCAP-over-IP -> $TULIP_DIR/.env

Open Tulip and watch flows appear. If none show:
  - can Tulip reach it?   nc -vz $VULN_IP $BROKER_PORT
  - broker log on vulnbox: /tmp/tulip-capture.log
  - make sure the filter matches real service ports.
The broker is a detached process; re-run this script after a vulnbox reboot.
=======================================================
EOF
