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

## What you do once (host-side; ~10 min) — can be done now

Run these on the Command Center VM (`~/adcc-command-center` is the app checkout).

1. **DNS.** Add an `A` record `tulip.itikad.site` → the VM's public IP (same IP
   as `itikad.site`). Caddy obtains the TLS cert automatically once this resolves.

2. **Firewall.** Confirm the cloud firewall (Azure NSG / UFW) exposes only
   **80 and 443** to the public internet. Tulip's port 3000 must NOT be public —
   it is reached only through Caddy. (Basic auth is the second layer.)

3. **Get Tulip and apply our overrides.**
   ```bash
   cd ~
   git clone https://github.com/OpenAttackDefenseTools/tulip.git
   cd tulip
   cp ~/adcc-command-center/deploy/tulip/tulip.env.example .env
   cp ~/adcc-command-center/deploy/tulip/configurations.py.example services/api/configurations.py
   # edit .env and configurations.py later with the real game values
   ```

4. **Start Tulip (tuned).**
   ```bash
   docker compose \
     -f docker-compose.yml \
     -f ~/adcc-command-center/deploy/tulip/docker-compose.override.yml \
     up -d --build
   # sanity check from the host: should return HTML
   curl -sS http://127.0.0.1:3000 | head -c 200
   ```

5. **Publish it through Caddy (gated).** Generate a password hash and drop the
   site file into the Command Center's Caddy `conf.d` volume:
   ```bash
   cd ~/adcc-command-center
   # pick a strong shared password; this prints a $2a$... hash
   docker compose exec web caddy hash-password --plaintext 'YOUR-STRONG-PASSWORD'

   # write the drop-in (replace the hash), then reload Caddy
   cp deploy/tulip/tulip.caddy.example /tmp/tulip.caddy
   #   edit /tmp/tulip.caddy: paste the hash after "team", confirm the hostname
   docker compose cp /tmp/tulip.caddy web:/etc/caddy/conf.d/tulip.caddy
   docker compose exec web caddy reload --config /etc/caddy/Caddyfile
   ```
   Visit **https://tulip.itikad.site** — you should get a basic-auth prompt, then
   the Tulip UI. The sidebar link now works for the whole team.

   To take it down later: `docker compose exec web rm /etc/caddy/conf.d/tulip.caddy && docker compose exec web caddy reload --config /etc/caddy/Caddyfile`.

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
