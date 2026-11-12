# Destructive Farm — hosting runbook

[Destructive Farm](https://github.com/DestructiveVoice/DestructiveFarm) is an
Attack & Defense exploit farm: it runs your attack scripts ("sploits") against
every opponent team each tick and automatically submits the flags they capture.
It is a separate stack from the Command Center; the Command Center links to it
at **https://df.itikad.site**.

Upstream ships no Docker files, so this directory provides them.

## One-command setup

On the Command Center VM (over SSH):

```bash
cd ~/adcc-command-center && git pull && bash deploy/destructive-farm/setup.sh
```

That clones Destructive Farm, builds it, sets the login password, starts it, and
publishes `https://df.itikad.site`. Idempotent — safe to re-run. Override the
password with `DF_PW='...' bash deploy/destructive-farm/setup.sh`.

Log in at https://df.itikad.site with **any username** and the farm password
(Destructive Farm uses HTTP basic auth via `SERVER_PASSWORD`).

## Game day — configure the farm

Edit `~/destructive-farm/server/config.py` (the server reloads it automatically
every few seconds):

- `TEAMS` — map of team name → vulnbox IP for every opponent.
- `FLAG_FORMAT` — the flag regex the organisers publish.
- `SYSTEM_PROTOCOL` — the submitter protocol; must match a module in
  `server/protocols/` (e.g. `ructf_tcp`, `ructf_http`, `forcad_tcp`).
- `SYSTEM_HOST` / `SYSTEM_PORT` / `SYSTEM_URL` / `SYSTEM_TOKEN` — the organisers'
  flag-submission endpoint and credentials.
- `SUBMIT_FLAG_LIMIT`, `SUBMIT_PERIOD`, `FLAG_LIFETIME` — submit batching/timing.

Then add your attack scripts in the UI; the farm runs each one against every
team IP per tick and submits what they print.

Reset before a round: delete the SQLite db and restart —
`cd ~/destructive-farm && rm -f server/flags.sqlite && docker compose restart farm`.

## Security

- Port 5000 is published on the host but the cloud firewall exposes only 80/443,
  so the farm is reachable only through Caddy (`df.itikad.site`) over HTTPS.
- Destructive Farm's own login (`SERVER_PASSWORD`) is the gate. Change it from
  the default and rotate after the event. Keep the farm off the public internet.
- The flag farm runs YOUR scripts against opponents only — point it at the
  authorised game network, never outside it.
