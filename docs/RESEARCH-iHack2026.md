# A&D Operations Upgrade: Research and Gap Analysis

Research for the iHack 2026 (Nov 17-18) upgrade. Historical techniques below are
from 2022/2024 events and are references only. **The 2026 rules, network and
architecture may differ and must be confirmed with the organisers.** We do not
copy unsafe historical defaults (disabled SSH host verification, unbounded
capture, fetch-and-execute, blind process killing).

## Sources
- iHack 2022 A&D prep repo: `github.com/WesleyWong420/iHack-Attack-Defense`
- iHack 2024 semi-final writeup: `vicevirus.github.io/posts/ihack-2024-semi-final-writeup/`
- pkappa2 packet analysis: `github.com/spq/pkappa2`

## Practical lessons

### Defense / patching (highest-scoring in both writeups)
- A patch is only good if the **service still works**. 2024 examples that failed
  or were fragile: a file-deletion loop (killed fast by others), adding `.phar`
  to a filter (flag still leaked), hard-coding a variable (quick but narrow),
  and `pickle.loads('')` which likely breaks valid orders (unhandled `TypeError`).
- Takeaway: every patch needs a **functional regression check**, not just
  "exploit stops working". Keep a rollback ready.

### Attack workflow and script reuse
- 2022 `sshrunner.py`: a bounded tick loop (`tickinterval = 5*60`) over operator
  `.sh` scripts, running each, extracting flags, submitting them. Flag submission
  was **commented out** (gated) in the repo. This is the model for "Attack Jobs":
  reusable operator scripts, bounded sequential runs, flag extraction, manual gate.
- Real exploits were short Python `requests` scripts (custom headers / UA bypass),
  raw payloads reused **from access logs**, APK decompilation to find endpoints,
  and insecure deserialization (base64 pickle). pwntools for binaries.

### Persistence (detection, not deployment)
- Seen: SSH `authorized_keys` injection, hidden PHP web shells, a C daemon
  renamed to `nginx` that forks a shell and reconnects, cron/fetch-and-execute.
- Detection commands from the writeups: `ps -ef --forest` (disguised processes),
  `ss -anp`, `/proc/<pid>/cwd`, checking `authorized_keys` and web roots, reading
  access logs. These are read-only and safe.

### Packet capture / SOC
- The recommended collector is **tcpdump with rotation** (`-G 30 -z <script>`)
  that curls each finished pcap to an ingestor, excluding SSH and the upload
  traffic itself. This matches our existing PCAP ingestion.
- pkappa2 ingests via HTTP `POST /upload`, a watch directory, or PCAP-over-IP;
  it has flag-regex search (`flag_in`/`flag_out`) but **no documented stable REST
  API**. So we reference it and support the same tcpdump->rotate->import pipeline,
  rather than deep-coupling. Capture must stay **bounded** (size/rotation limits).
- Do not assume capture on our Azure VM can see the organiser's private network.
  Provide a **local capture + import** workflow for restricted environments.

### Docker
- Patch/redeploy pattern: `docker compose build` then `up --force-recreate -d`;
  capture evidence before rebuild (rebuild wipes in-container state). Keep data
  in named volumes. Keep a known-good image for rollback. Never `down -v`.

## Gap analysis (what exists vs. what this upgrade adds)

| Capability | Status before | This upgrade |
|---|---|---|
| Deterministic code analysis + Semgrep + patches | Exists (Defense) | Add before/after diff + functional-regression emphasis + patch export/history |
| PCAP ingestion + SOC offense correlation | Exists (SOC) | Add a tcpdump capture **wizard** (bounded command generator) + capture guide |
| Recon (tcp/banner/http) | Exists (Attack) | Add an **RCE script generator** (http/tcp/requests/pwntools, export, no exec) |
| Sandboxed local utility runner | Exists (Automation) | Reused as the model for operator-reviewed script execution (kept gated) |
| Persistence / IR guidance | None | Add **Persistence reference + investigation** read-only command guides |
| Docker operations / recovery | None | Add **Docker ops + container recovery** guides with a patch/deploy checklist |
| Attack Jobs (bounded script runs) | None | Scoped: management + server-side target allowlist + emergency stop; execution stays in the gated local sandbox worker, off by default |

## Safety stance (unchanged, enforced)
- No runtime AI. No mandatory GitHub/internet at match time. No uncontrolled downloads.
- The public FastAPI backend is never an arbitrary command-execution service.
- Operator scripts and untrusted binaries run only in the separate gated sandbox
  worker (non-root, no network, rlimits, no host secrets, no Docker socket), or
  are exported for local manual execution. High-risk execution stays **off** until
  explicitly approved.
- All target validation is server-side against the registered authorised scope.
- Destructive host/container actions are guidance only and require human action;
  the app never kills processes, deletes files, or changes SSH.

## Requires organiser clarification before match use
- Flag format and submission API (auto-submit stays gated until confirmed).
- Whether active recon / exploitation against opponents and a local pwn/attack
  sandbox are permitted.
- The network layout (can any capture point see opponent traffic?) and the
  registry used for Docker push/pull.
