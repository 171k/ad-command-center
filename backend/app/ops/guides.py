"""Curated operational guides (deterministic content, no execution).

Each guide is reference material for a time-limited A&D competition: short,
practical, with copyable commands that use <PLACEHOLDERS> and explicit warnings.
Read-only investigation commands are preferred; destructive actions are called
out and left for a human to run deliberately. Served to the UI via /api/ops/guides.
"""
from __future__ import annotations


def _cmd(cmd, note="", danger=False):
    return {"cmd": cmd, "note": note, "danger": danger}


GUIDES: list[dict] = [
    {
        "id": "packet-capture",
        "title": "Packet capture with tcpdump",
        "workspace": "soc",
        "summary": "Capture bounded, rotated PCAPs on an authorised interface and import them into the SOC.",
        "sections": [
            {
                "heading": "Find the right interface",
                "body": "Identify the interface that carries the service traffic. Do not guess eth0.",
                "commands": [
                    _cmd("ip -brief addr", "List interfaces and their IPs."),
                    _cmd("sudo tcpdump -D", "List interfaces tcpdump can use."),
                ],
            },
            {
                "heading": "Capture (bounded + rotated)",
                "body": "Rotate by time and cap the number of files so disk stays bounded. "
                        "-s 0 keeps full packets. Exclude SSH and your own upload traffic.",
                "commands": [
                    _cmd("sudo tcpdump -i <IFACE> -n -s 0 -w ./captures/cap.pcap '(port <PORT>) and not port 22'",
                         "Single-file capture. Ctrl-C to stop."),
                    _cmd("sudo tcpdump -i <IFACE> -n -s 0 -G 30 -W 60 -w ./captures/cap-%Y%m%d-%H%M%S.pcap '(port <PORT>) and not port 22'",
                         "Rotate every 30s, keep 60 files (30 min window). Use the Capture wizard to build this."),
                ],
            },
            {
                "heading": "Stop and inspect",
                "body": "Stop with Ctrl-C (or kill the pid). Inspect before importing.",
                "commands": [
                    _cmd("sudo pkill -INT tcpdump", "Stop a backgrounded capture cleanly."),
                    _cmd("tcpdump -nr ./captures/cap.pcap | head", "Peek at a capture."),
                    _cmd("capinfos ./captures/cap.pcap", "Summary (needs wireshark-common)."),
                ],
            },
            {
                "heading": "Transfer and import",
                "body": "Copy the PCAP from the authorised host, then import it in SOC -> Events (PCAP). "
                        "Keep captures small; do not collect unrelated traffic.",
                "commands": [
                    _cmd("scp user@<HOST>:./captures/cap.pcap .", "Pull a capture from the authorised host."),
                ],
            },
            {
                "heading": "Containers and namespaces",
                "body": "Inside a container the host interface may be invisible. Capture on the host, "
                        "or enter the container's network namespace from the host.",
                "commands": [
                    _cmd("PID=$(docker inspect -f '{{.State.Pid}}' <CONTAINER>); sudo nsenter -t $PID -n tcpdump -i any -w ./captures/ctr.pcap",
                         "Capture inside a container's netns from the host."),
                ],
            },
        ],
        "warnings": [
            "Capture only on hosts/interfaces you are authorised to monitor.",
            "Do not assume a capture point can see the organiser's private network or opponent traffic.",
            "Bound storage with -W; never fill the disk. Avoid capturing sensitive unrelated traffic.",
        ],
    },
    {
        "id": "persistence-reference",
        "title": "Linux persistence reference",
        "workspace": "soc",
        "summary": "Where attackers hide persistence and how to spot it with read-only commands. An unfamiliar service is not automatically malicious.",
        "sections": [
            {
                "heading": "Cron jobs",
                "body": "Scheduled re-execution. Check user and system crontabs and drop-in dirs.",
                "commands": [
                    _cmd("for u in $(cut -f1 -d: /etc/passwd); do crontab -l -u $u 2>/dev/null; done", "All user crontabs."),
                    _cmd("ls -la /etc/cron.* /etc/crontab /var/spool/cron* 2>/dev/null", "System cron locations."),
                ],
            },
            {
                "heading": "systemd services and timers",
                "body": "A unit that restarts a backdoor. Look for recently changed or oddly named units.",
                "commands": [
                    _cmd("systemctl list-unit-files --type=service --state=enabled", "Enabled services."),
                    _cmd("systemctl list-timers --all", "Timers."),
                    _cmd("ls -lat /etc/systemd/system /lib/systemd/system | head", "Recently modified units."),
                ],
            },
            {
                "heading": "Shell startup files",
                "body": "Commands that run on login/shell start.",
                "commands": [
                    _cmd("ls -la ~/.bashrc ~/.bash_profile ~/.profile /etc/profile.d/ 2>/dev/null", "Startup files."),
                ],
            },
            {
                "heading": "SSH authorized_keys",
                "body": "Injected keys grant silent access. Compare against keys you placed.",
                "commands": [
                    _cmd("find / -name authorized_keys 2>/dev/null -exec ls -la {} \\; -exec cat {} \\;", "Find and show all authorized_keys."),
                ],
            },
            {
                "heading": "Users, processes, ports",
                "body": "Unexpected users, disguised long-running processes (e.g. a child named 'nginx'), "
                        "and unexpected listeners.",
                "commands": [
                    _cmd("awk -F: '$3>=1000{print $1,$3,$7}' /etc/passwd", "Human/added users."),
                    _cmd("ps -ef --forest", "Process tree; spot disguised children and odd parents."),
                    _cmd("ss -tulpn", "Listening TCP/UDP ports and owning processes."),
                ],
            },
            {
                "heading": "Web roots and writable dirs",
                "body": "Hidden web shells (e.g. .home.php) and new files in writable paths.",
                "commands": [
                    _cmd("find /var/www -newermt '-2 hours' -type f 2>/dev/null", "Recently changed web files."),
                    _cmd("find /tmp /dev/shm -type f -mmin -120 2>/dev/null", "Recent files in writable dirs."),
                ],
            },
            {
                "heading": "Container entrypoints",
                "body": "A changed entrypoint/cmd can re-launch a backdoor on restart.",
                "commands": [
                    _cmd("docker inspect -f '{{.Config.Entrypoint}} {{.Config.Cmd}}' <CONTAINER>", "Entrypoint and cmd."),
                ],
            },
        ],
        "warnings": [
            "These are read-only. An unfamiliar process or unit is NOT automatically malicious; confirm before acting.",
            "Preserve evidence (copy files, save command output) before any change.",
        ],
    },
    {
        "id": "persistence-investigation",
        "title": "Persistence investigation and removal",
        "workspace": "soc",
        "summary": "A disciplined workflow: detect, record evidence, identify, contain without breaking scored services, remove manually, verify.",
        "sections": [
            {
                "heading": "1-4. Identify and record",
                "body": "Record evidence first. Identify the process, its parent, and its connections.",
                "commands": [
                    _cmd("ps -ef --forest | tee evidence_ps.txt", "Full tree, saved as evidence."),
                    _cmd("sudo ls -l /proc/<PID>/exe /proc/<PID>/cwd; sudo cat /proc/<PID>/cmdline | tr '\\0' ' '",
                         "Binary path, working dir, full command line."),
                    _cmd("sudo ss -tanp | grep <PID>", "Network connections for the process."),
                    _cmd("sudo lsof -p <PID> 2>/dev/null | tee evidence_lsof_<PID>.txt", "Open files/sockets."),
                ],
            },
            {
                "heading": "5-6. Startup mechanism and authorisation",
                "body": "Find what restarts it (cron/systemd/startup/container). Decide whether it is authorised.",
                "commands": [
                    _cmd("systemctl status <UNIT>", "If a unit launched it."),
                    _cmd("grep -rl <PID_OR_NAME> /etc/cron* /etc/systemd 2>/dev/null", "Where it is referenced."),
                ],
            },
            {
                "heading": "7-10. Contain, remove, verify (manual)",
                "body": "Plan containment that does NOT break a scored service. Disable the mechanism, then stop "
                        "the process, then verify it does not restart and the real service still works.",
                "commands": [
                    _cmd("sudo systemctl disable --now <UNIT>", "Disable a confirmed-malicious unit.", danger=True),
                    _cmd("sudo kill <PID>   # then confirm it does not respawn", "Stop the process after disabling its restart.", danger=True),
                    _cmd("curl -fsS http://localhost:<SERVICE_PORT>/health || echo 'SERVICE DOWN'", "Verify the legitimate service still responds."),
                ],
            },
        ],
        "warnings": [
            "Never auto-kill, delete, or disable. Confirm it is malicious and get a human go-ahead first.",
            "Do not alter SSH access or remove data volumes.",
            "Keep an incident timeline: time, observation, action, result.",
        ],
    },
    {
        "id": "docker-operations",
        "title": "Docker operations (pull / build / tag / push)",
        "workspace": "defense",
        "summary": "Patch a service image and ship it. Registry URL, credentials, image and tag are configurable; never hard-code secrets.",
        "sections": [
            {
                "heading": "Pull and inspect",
                "body": "Get the current image and read it before changing anything.",
                "commands": [
                    _cmd("docker pull <REGISTRY>/<IMAGE>:<TAG>", "Pull the target image."),
                    _cmd("docker image inspect <REGISTRY>/<IMAGE>:<TAG> | less", "Metadata, env, entrypoint, layers."),
                    _cmd("docker history --no-trunc <REGISTRY>/<IMAGE>:<TAG>", "How it was built."),
                ],
            },
            {
                "heading": "Build a patched image",
                "body": "Edit the source/Dockerfile, build with a new tag, keep the old tag for rollback.",
                "commands": [
                    _cmd("docker build -t <REGISTRY>/<IMAGE>:<NEWTAG> .", "Build the patched image."),
                    _cmd("docker tag <REGISTRY>/<IMAGE>:<TAG> <REGISTRY>/<IMAGE>:prev", "Keep a rollback tag before replacing."),
                ],
            },
            {
                "heading": "Authenticate and push",
                "body": "Log in without putting the password on the command line; verify the pushed digest.",
                "commands": [
                    _cmd("echo \"$REG_PASS\" | docker login <REGISTRY> -u <USER> --password-stdin", "Login via stdin (no secret in history)."),
                    _cmd("docker push <REGISTRY>/<IMAGE>:<NEWTAG>", "Push the patched image."),
                    _cmd("docker buildx imagetools inspect <REGISTRY>/<IMAGE>:<NEWTAG>", "Verify the pushed digest."),
                ],
            },
            {
                "heading": "Without a registry",
                "body": "Move an image by file when the organiser has no reachable registry.",
                "commands": [
                    _cmd("docker save <REGISTRY>/<IMAGE>:<NEWTAG> -o image.tar", "Export to a tarball."),
                    _cmd("docker load -i image.tar", "Import on the target host."),
                ],
            },
        ],
        "warnings": [
            "Do not assume Docker Hub or GHCR; the organiser's registry URL is a parameter.",
            "Never store registry credentials in source or image layers. Use env + --password-stdin.",
        ],
    },
    {
        "id": "container-recovery",
        "title": "Container defense and recovery",
        "workspace": "defense",
        "summary": "Inspect, patch, restart and roll back service containers with Docker Compose, without losing data.",
        "sections": [
            {
                "heading": "Inspect",
                "body": "See what is running, read logs and health, check mounts and networking.",
                "commands": [
                    _cmd("docker compose ps", "Running/stopped services."),
                    _cmd("docker compose logs --tail=100 <SERVICE>", "Recent logs."),
                    _cmd("docker inspect -f '{{.State.Health.Status}}' <CONTAINER>", "Health status."),
                    _cmd("docker inspect -f '{{json .Mounts}}' <CONTAINER> | python3 -m json.tool", "Bind mounts and volumes."),
                ],
            },
            {
                "heading": "Investigate inside",
                "body": "Look at processes and config inside a container without leaking secrets.",
                "commands": [
                    _cmd("docker exec <CONTAINER> ps -ef --forest", "Process tree inside the container."),
                    _cmd("docker exec <CONTAINER> env | grep -viE 'pass|secret|key|token'", "Env config with secrets filtered out."),
                ],
            },
            {
                "heading": "Patch, rebuild, restart",
                "body": "Rebuild only the changed service and recreate it. Capture evidence first; rebuild wipes "
                        "in-container state (keep data in named volumes).",
                "commands": [
                    _cmd("docker compose build <SERVICE> && docker compose up -d --force-recreate <SERVICE>", "Rebuild and recreate one service."),
                    _cmd("curl -fsS http://localhost:<PORT>/health || echo 'DOWN'", "Confirm it is healthy after."),
                ],
            },
            {
                "heading": "Roll back",
                "body": "Return to the known-good image if the patch breaks the service.",
                "commands": [
                    _cmd("docker tag <IMAGE>:prev <IMAGE>:latest && docker compose up -d --force-recreate <SERVICE>", "Roll back to the saved image."),
                ],
            },
        ],
        "warnings": [
            "NEVER run 'docker compose down -v' or 'docker volume rm' on a live service: -v deletes data volumes.",
            "Patch one service at a time; verify health before moving on.",
            "Operate without GitHub/registry if needed (docker save/load).",
        ],
    },
]

GUIDES_BY_ID = {g["id"]: g for g in GUIDES}


def list_guides() -> list[dict]:
    return [{"id": g["id"], "title": g["title"], "workspace": g["workspace"], "summary": g["summary"]}
            for g in GUIDES]


def get_guide(gid: str) -> dict | None:
    return GUIDES_BY_ID.get(gid)


def search_guides(q: str) -> list[dict]:
    ql = (q or "").lower().strip()
    if not ql:
        return list_guides()
    out = []
    for g in GUIDES:
        hay = (g["title"] + g["summary"] + g["workspace"]).lower()
        for s in g["sections"]:
            hay += (s["heading"] + s.get("body", "")).lower()
            for c in s.get("commands", []):
                hay += (c["cmd"] + c.get("note", "")).lower()
        if ql in hay:
            out.append({"id": g["id"], "title": g["title"], "workspace": g["workspace"], "summary": g["summary"]})
    return out
