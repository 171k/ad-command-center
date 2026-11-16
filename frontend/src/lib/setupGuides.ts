// Curated setup guidance. Commands target Ubuntu/Debian/Kali unless noted.
// These mirror the official package names and flags; verify versions on your host.

export type Guide = {
  id: string;
  tool: string;
  purpose: string;
  platforms: string;
  steps: { label: string; cmd?: string; note?: string }[];
  verify?: string;
  troubleshoot?: { problem: string; fix: string }[];
};

export const GUIDES: Guide[] = [
  {
    id: "tcpdump",
    tool: "tcpdump",
    purpose: "Capture packets to rotating PCAP files for a specific service, so you can replay traffic into the SOC later.",
    platforms: "Ubuntu · Debian · Kali",
    steps: [
      { label: "Install", cmd: "sudo apt-get update && sudo apt-get install -y tcpdump" },
      { label: "List interfaces", cmd: "ip -br addr" },
      { label: "Capture one service with file rotation (100MB x 10 files)", cmd: "sudo tcpdump -i eth0 -w /var/pcaps/svc-%Y%m%d-%H%M%S.pcap -C 100 -W 10 'tcp port 8080'", note: "-C size(MB) -W keep N files; the BPF filter limits capture to the target port so the disk does not fill." },
      { label: "Drop privileges / limit snaplen", cmd: "sudo tcpdump -i eth0 -s 0 -Z nobody -w /var/pcaps/svc.pcap 'host 10.10.0.5'" },
    ],
    verify: "ls -lh /var/pcaps && sudo tcpdump -r /var/pcaps/svc.pcap -c 5",
    troubleshoot: [
      { problem: "Permission denied", fix: "Run with sudo or grant capabilities: sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)" },
      { problem: "Disk filling up", fix: "Use -C and -W to cap total size; mount /var/pcaps on a separate volume." },
    ],
  },
  {
    id: "suricata",
    tool: "Suricata",
    purpose: "Network IDS that emits EVE JSON alerts/HTTP records, the primary feed for the SOC.",
    platforms: "Ubuntu · Debian",
    steps: [
      { label: "Install (official PPA has current builds)", cmd: "sudo add-apt-repository ppa:oisf/suricata-stable && sudo apt-get update && sudo apt-get install -y suricata" },
      { label: "Set the monitored interface", cmd: "sudo suricata-update && sudo sed -i 's/^\\( *\\)- interface: .*/\\1- interface: eth0/' /etc/suricata/suricata.yaml" },
      { label: "Confirm EVE JSON output is enabled", note: "In /etc/suricata/suricata.yaml, under outputs → eve-log, ensure `enabled: yes`, `filetype: regular`, `filename: eve.json` and the `types` list includes alert, http, flow, fileinfo." },
      { label: "Enable payload capture on alerts", note: "Set `payload: yes` and `payload-printable: yes` under the alert eve type so the SOC can show what was sent." },
      { label: "Run", cmd: "sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -D" },
      { label: "Forward EVE to the SOC (see seeded script)", cmd: "SENSOR_TOKEN=... URL=https://host/api/soc/ingest/sensor EVE=/var/log/suricata/eve.json ./eve-forward.sh" },
    ],
    verify: "sudo tail -f /var/log/suricata/eve.json | grep -m1 event_type",
    troubleshoot: [
      { problem: "No events in SOC", fix: "Confirm eve.json is growing, the sensor token is valid and the forwarder reaches /api/soc/ingest/sensor (check Sensors → last seen)." },
      { problem: "High CPU", fix: "Reduce ruleset with suricata-update --disable-conf or pin the capture to the target port via BPF: suricata ... --bpf-filter 'port 8080'." },
    ],
  },
  {
    id: "tshark",
    tool: "Wireshark / TShark",
    purpose: "Inspect captured PCAPs and extract HTTP transactions for manual analysis.",
    platforms: "Ubuntu · Debian · Kali · Windows/WSL2",
    steps: [
      { label: "Install", cmd: "sudo apt-get install -y tshark" },
      { label: "Allow non-root capture (optional)", cmd: "sudo dpkg-reconfigure wireshark-common && sudo usermod -aG wireshark $USER" },
      { label: "Extract HTTP requests from a PCAP", cmd: "tshark -r svc.pcap -Y http.request -T fields -e ip.src -e http.request.method -e http.request.full_uri" },
      { label: "Export objects", cmd: "tshark -r svc.pcap --export-objects http,./objects" },
    ],
    verify: "tshark -v",
  },
  {
    id: "zeek",
    tool: "Zeek",
    purpose: "Rich connection/HTTP metadata and notices that complement Suricata alerts.",
    platforms: "Ubuntu · Debian",
    steps: [
      { label: "Install", cmd: "sudo apt-get install -y zeek  # or from https://download.zeek.org" },
      { label: "Run against an interface", cmd: "sudo zeek -i eth0 LogAscii::use_json=T" },
      { label: "Run against a PCAP", cmd: "zeek -r svc.pcap LogAscii::use_json=T" },
    ],
    verify: "ls *.log  # conn.log, http.log, notice.log",
    troubleshoot: [{ problem: "Too much data on 4GB VPS", fix: "Prefer running Zeek on a separate collector host and forward only http.log/notice.log." }],
  },
  {
    id: "tulip",
    tool: "Tulip (OpenAttackDefenseTools)",
    purpose: "A/D traffic browser — ingests pcaps, reassembles flows, generates replay scripts. Hosted at tulip.itikad.site behind a login (user: team).",
    platforms: "Docker · on the Command Center VM",
    steps: [
      { label: "One-command setup — run on the iHack server over SSH", cmd: "cd ~/adcc-command-center && git pull && bash deploy/tulip/setup.sh", note: "Clones Tulip, applies the resource + toolchain fixes, starts it, and publishes https://tulip.itikad.site (user: team). Idempotent — safe to re-run." },
      { label: "Open it", note: "Click Tulip in the sidebar or go to https://tulip.itikad.site. Login user is 'team'." },
      { label: "Game day — set the real values", note: "Edit ~/tulip/.env (TICK_START, TICK_LENGTH, FLAG_REGEX, VM_IP, TEAM_ID) and the service list in ~/tulip/services/api/configurations.py, then rebuild the api: docker compose -f ~/tulip/docker-compose.yml -f ~/adcc-command-center/deploy/tulip/docker-compose.override.yml up -d --build api" },
      { label: "Game day — feed it traffic (one command)", cmd: "bash deploy/tulip/capture-setup.sh", note: "Run where your local Tulip is, on the game network. It asks for the vulnbox IP + SSH password, starts a tcpdump->socat PCAP-over-IP broker on the vulnbox (filtered to your service ports, SSH excluded), and links it into Tulip. Tulip must be able to reach the vulnbox. Manual file/stream options are in deploy/tulip/README.md." },
    ],
    verify: "curl -sS -o /dev/null -w '%{http_code}\\n' https://tulip.itikad.site   # 401 = login required = working",
    troubleshoot: [
      { problem: "Blank page or 502", fix: "Tulip not up — re-run bash deploy/tulip/setup.sh, then check docker logs tulip-frontend-1 / tulip-api-1." },
      { problem: "No flows showing", fix: "No traffic yet — feed pcaps into the traffic dir (game day); the bundled demo pcaps confirm the pipeline works." },
    ],
  },
  {
    id: "destructive-farm",
    tool: "Destructive Farm",
    purpose: "A/D exploit farm — runs your attack scripts against every opponent each tick and auto-submits flags. Hosted at df.itikad.site behind a login.",
    platforms: "Docker · on the Command Center VM",
    steps: [
      { label: "One-command setup — run on the iHack server over SSH", cmd: "cd ~/adcc-command-center && git pull && bash deploy/destructive-farm/setup.sh", note: "Clones Destructive Farm, builds it (upstream has no Docker), starts it, and publishes https://df.itikad.site. Idempotent — safe to re-run." },
      { label: "Open it", note: "Go to https://df.itikad.site and log in with any username and the farm password." },
      { label: "Game day — configure the farm", note: "Edit ~/destructive-farm/server/config.py: TEAMS (name -> vulnbox IP), FLAG_FORMAT, SYSTEM_PROTOCOL + SYSTEM_HOST/PORT/TOKEN (the organiser's submitter), SUBMIT_FLAG_LIMIT, FLAG_LIFETIME. The server reloads config.py automatically." },
      { label: "Add your sploits", note: "Register attack scripts in the UI; the farm runs each one against every team IP per tick and submits the flags they print." },
    ],
    verify: "curl -sS -o /dev/null -w '%{http_code}\\n' https://df.itikad.site   # 401 = login required = working",
    troubleshoot: [
      { problem: "Flags not submitted", fix: "SYSTEM_PROTOCOL must match a module in server/protocols/, and SYSTEM_HOST/PORT/TOKEN must be the organiser's submitter. Watch docker logs destructive-farm." },
      { problem: "Reset before a round", fix: "cd ~/destructive-farm && rm -f server/flags.sqlite && docker compose restart farm" },
    ],
  },
];
