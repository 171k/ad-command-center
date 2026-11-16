# Local / offline setup — one command

Run the whole A&D stack on one machine (a laptop, or a box on the competition
LAN), plain HTTP on localhost. No public domain, TLS, Azure or Tailscale.

```bash
git clone https://github.com/171k/ad-command-center.git
cd ad-command-center
bash deploy/local/setup.sh
```

Options: `APP_PW=<min 10 chars> DF_PW=<pw> bash deploy/local/setup.sh`.

Brings up:

| Service | URL | Login |
|---|---|---|
| Command Center | http://localhost:8080 | users `itik mejik gha namia`, the `APP_PW` (itik is admin) |
| Tulip | http://localhost:3000 | none (localhost only) |
| Destructive Farm | http://localhost:5000 | any username / `DF_PW` |

…plus the Tulip control agent, so **Network/SOC → Tulip → Save & Rebuild** works
locally (fill the form, click, the agent rebuilds the local Tulip).

Requirements: `docker` (with compose v2), `git`, `python3`, `bash`. Idempotent —
re-run any time. On Windows use WSL.

Notes:
- This is a **separate instance** with its own fresh database — it does not share
  findings/patches with the hosted itikad.site instance.
- It is HTTP-only and meant for localhost / the game LAN. Keep the host off the
  public internet.
- The one-command tool scripts (`deploy/tulip/setup.sh`,
  `deploy/destructive-farm/setup.sh`) honour `ADCC_LOCAL=1`, which skips the
  public Caddy/TLS publish and leaves each tool on its localhost port.
