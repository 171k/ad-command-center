# Network data collection

The SOC ingests **real** telemetry. Nothing on the dashboard is faked; with no
data it shows an empty state explaining how to connect a feed.

## Ingestion paths

| Path | Endpoint | Auth | Notes |
|---|---|---|---|
| Suricata EVE (live) | `POST /api/soc/ingest/sensor` | Sensor bearer token | NDJSON or JSON array; malformed lines skipped |
| Session ingest | `POST /api/soc/ingest` | Session + CSRF | `{events:[EVE…], access_logs:[…]}` for manual/test use |
| PCAP upload | `POST /api/soc/ingest/pcap` | Session + CSRF | Needs tshark; HTTP requests extracted |

### Suricata EVE

Enable EVE JSON with alert/http/flow/fileinfo and payload capture (see the
in-app **Setup** guide). Forward with the seeded script
(`Suricata EVE tail -> Command Center`), which `tail -F`s `eve.json` and POSTs each
line to the sensor endpoint with a token from **SOC → Sensors**.

### PCAP

Upload `.pcap`/`.pcapng` in **SOC → Sensors → Upload PCAP**. The server validates
magic bytes, caps size (`ADCC_MAX_UPLOAD_BYTES`), and runs
`tshark -Y http.request -T fields …` out-of-process to extract HTTP transactions,
which flow through the normal correlation path. Without tshark the feature is
disabled and says so; other ingestion still works.

### Reverse-proxy / application logs

Ship structured HTTP access logs as `access_logs` rows (`src_ip`, `method`, `url`,
`query`, `status`, `host`, optional `response_body` for outcome evidence). **Do not
log** passwords, cookies, or authorization headers. Request-body logging must be a
deliberate, scoped choice at the app/proxy layer.

## TLS visibility — important

Passive PCAP of HTTPS shows the handshake and SNI but **not** decrypted request or
response bodies. You cannot classify most app-layer outcomes from encrypted PCAP
alone. For full payload visibility use one of:

- Capture at the **TLS-termination point** (reverse proxy) where traffic is plaintext.
- Enable scoped **application-level logging** (method/URL/body/status) and ship it
  as access logs.
- Use a key-log / MITM setup **only** if the competition authorizes it.

The app never claims payload visibility it does not have; it shows "Payload
unavailable" when bytes are absent.

## Sensor architecture

Run collectors (Suricata/Zeek) on a **separate** host or the competition-provided
machine, subject to organizer rules. Each sensor authenticates with a scoped,
ingestion-only bearer token (hashed at rest) that grants no admin access. Restrict
which sensors may submit; where outbound network is forbidden, use file-based
ingestion via the session endpoint instead.

## Tulip (optional)

Tulip has no stable public API, so integration is file-based / deep-link: share the
same PCAPs and link out to the Tulip UI by service/time. Run Tulip on the collector
host, not the 4 GB app VPS. The SOC is fully usable without it.

## Troubleshooting

| Symptom | Check |
|---|---|
| No events arriving | `eve.json` growing? sensor token valid? forwarder reaching the endpoint? **Sensors → last seen** |
| PCAP "tshark not installed" | Install Wireshark/TShark; re-check **Upload PCAP** status |
| Events but no offenses | Confirm the technique classifier matches (check **Events** category); unknown traffic is `other` |
| High CPU on the collector | Trim Suricata rules; pin capture to the target port via BPF |
