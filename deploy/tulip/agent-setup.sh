#!/usr/bin/env bash
# Install + start the Tulip control agent on the Command Center host.
#
#   cd ~/adcc-command-center && git pull && bash deploy/tulip/agent-setup.sh
#
# The agent runs as this user (who has Docker access) and watches the shared
# control dir for rebuild requests from the web app. It persists via an @reboot
# crontab entry and is started immediately. Idempotent.
set -euo pipefail

ADCC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTROL="$ADCC/control"
AGENT="$ADCC/deploy/tulip/control-agent.py"
LOG="$CONTROL/agent.log"

# Shared dir: writable by both the backend container (root) and this user.
mkdir -p "$CONTROL"
chmod 0777 "$CONTROL"

# Persist across reboots.
CRON_LINE="@reboot cd $ADCC && nohup python3 $AGENT >> $LOG 2>&1 &"
( crontab -l 2>/dev/null | grep -v 'tulip/control-agent.py' || true; echo "$CRON_LINE" ) | crontab -
echo "installed @reboot cron entry"

# Start now if not already running.
if pgrep -f 'tulip/control-agent.py' >/dev/null 2>&1; then
  echo "agent already running (pid $(pgrep -f 'tulip/control-agent.py' | tr '\n' ' '))"
else
  cd "$ADCC"
  nohup python3 "$AGENT" >> "$LOG" 2>&1 &
  sleep 1
  echo "agent started (pid $(pgrep -f 'tulip/control-agent.py' | tr '\n' ' '))"
fi
echo "log: $LOG"
