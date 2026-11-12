# Tulip dashboard — hosting runbook

[Tulip](https://github.com/OpenAttackDefenseTools/tulip) is a traffic-analysis
dashboard for Attack & Defense CTF: it ingests pcaps, reassembles them into
flows, lets you browse/tag attacks and generates Python snippets to replay them.
It is a **separate stack** from the Command Center; the Command Center just links
to it at **https://tulip.itikad.site** and proxies to it.

## What is already wired (in this repo, deploys automatically)

- **Nav link** "Tulip" in the Command Center's Shared sidebar → `https://tulip.itikad.site`.
- **Caddy** imports any drop-in site file from a persistent `conf.d` volume
  (no-op until you add one) and can reach a host-published stack via
  `host.docker.internal`.
- **`tulip.caddy.example`** — the gated site block (TLS + HTTP basic auth).
- **`docker-compose.override.yml`** — trims Tulip's 128g shared-memory default so
  it starts on this VM.
- **`tulip.env.example`** / **`configurations.py.example`** — config templates.

## Setup — one command

Prereqs (once): add a DNS `A` record `tulip.itikad.site` → the VM's public IP
(same IP as `itikad.site`), and confirm the cloud firewall exposes only 80/443
(Tulip's port 3000 must not be public — Caddy reaches it internally).

Then, on the Command Center VM over SSH:

```bash
cd ~/adcc-command-center && git pull && bash deploy/tulip/setup.sh
```

`setup.sh` clones Tulip, applies the fixes below, starts it (resource-tuned),
and publishes `https://tulip.itikad.site` (user: `team`). It is idempotent.

What it handles for you (each was a real gotcha):
- Tulip's complete `.env` (the partial template missed `TRAFFIC_DIR_DOCKER`).
- Patches the timescale image to build without `clang-19` (`with_llvm=no`).
- Leaves `services/api/configurations.py` as upstream (webservice.py imports many
  names from it) — you edit it in place on game day.
- Drops in the gated Caddy site and restarts Caddy (validated first).

<details><summary>Manual equivalent (reference)</summary>

```bash
cd ~ && git clone https://github.com/OpenAttackDefenseTools/tulip.git && cd tulip
sed -i 's/make USE_PGXS=1 install/make USE_PGXS=1 with_llvm=no install/g' services/timescale/Dockerfile
cp .env.example .env
docker compose -f docker-compose.yml -f ~/adcc-command-center/deploy/tulip/docker-compose.override.yml up -d --build
cd ~/adcc-command-center
docker compose cp deploy/tulip/tulip.caddy.example web:/etc/caddy/conf.d/tulip.caddy
docker compose exec -T web caddy validate --config /etc/caddy/Caddyfile && docker compose restart web
```
</details>

To take it down later: `docker compose exec web rm /etc/caddy/conf.d/tulip.caddy && docker compose restart web` (and `docker compose -f ~/tulip/docker-compose.yml down` to stop Tulip).

## On game day

1. **Confirm the real values** with the organisers and edit, then restart the
   affected pieces:
   - `.env`: `TICK_START`, `TICK_LENGTH`, `FLAG_REGEX`, `VM_IP`, `TEAM_ID`.
   - `services/api/configurations.py`: the service list → `docker compose up -d --build api`.

2. **Feed it traffic** (pick one):
   - **File mode:** on the vulnbox, run a rotating capture and copy pcaps into
     Tulip's `TRAFFIC_DIR_HOST` (the assembler picks them up via inotify):
     ```bash
     # on the vulnbox
     tcpdump -i eth0 -G 180 -w 'traffic_%H-%M-%S.pcap' port 8080 or port 5555
     # ship them to the Tulip host (over Tailscale)
     rsync -avz -e ssh ./traffic_*.pcap user@<tulip-host>:~/tulip/pcaps/
     ```
     Our existing capture guide (SOC → packet-capture) produces exactly these.
   - **Live mode (PCAP-over-IP):** run a `pcap-broker` on the vulnbox and set
     `PCAP_OVER_IP` in `.env`, then `docker compose ... up -d assembler`.

3. (Optional) Point Tulip's `enricher` at Suricata's `eve.json` to tag flows
   with IDS alerts — use Tulip's `docker-compose-suricata.yml`. This dovetails
   with the SOC Suricata pipeline you already run.

## Notes & cautions

- Tulip has **no built-in auth**; the Caddy basic-auth drop-in is what protects
  it. Keep port 3000 off the public internet.
- Tulip's DB uses trust-auth on an internal network — do not publish 5432.
- There is **nothing to analyse until the game network is live**; standing it up
  early is just so it is tested and ready.
- The exploit-replay feature outputs Python snippets from a selected flow — you
  review and run them yourself; Tulip does not auto-attack.
