# A&D Command Center: Project Briefing

**Audience:** Project / engineering manager
**Status:** Working application, deployed and running
**Prepared:** 2026-11-07

---

## 1. One-paragraph summary

The A&D Command Center is a private, self-hosted web application that gives a
four-person Attack & Defense CTF team a single place to run their competition:
attack tooling, deterministic defensive code analysis, reusable automation and a
beginner-friendly **SIEM** that turns raw network alerts into a short, prioritized
list of "here's who is attacking us, here's what probably worked, here's the
evidence." It is a **real, functional platform**, not a mockup, built to run on a
small (~4 GB) server, fully offline, with **no AI at runtime**.

It is currently **live at `http://20.189.71.166`** on the team's Azure VM.

---

## 2. Why it exists (the problem)

In an A&D CTF, four people are simultaneously: patching their own vulnerable
services, attacking opponents and trying to tell, from thousands of automated
requests per minute, *which attacks against them actually succeeded*. Teams
normally juggle a dozen terminals, notes and tools. Beginners drown in noise and
miss the one request that stole a flag.

This platform centralizes that work and, crucially, answers the hard question, **"did it work?"**, with transparent, defensible evidence instead of guesswork.

---

## 3. How it works (architecture at a glance)

```
                    ┌──────────────────────────────────────┐
  Teammates ─HTTPS─▶│  Caddy (reverse proxy, static SPA)    │
  (4 browsers)      └───────────────┬──────────────────────┘
                                    │ /api
                    ┌───────────────▼──────────────────────┐
                    │  FastAPI backend (Python)             │
                    │  • Auth (shared account, 4 sessions)  │
                    │  • Defense analyzer (rule engine)     │
                    │  • SOC correlation + classification   │
                    │  • Live sync (Server-Sent Events)     │
                    └───────────────┬──────────────────────┘
                                    │
                    ┌───────────────▼───────┐   ┌──────────────────────┐
                    │  SQLite (WAL) + files  │   │  Sensors (optional): │
                    └────────────────────────┘   │  Suricata / tshark   │
                                                  └──────────────────────┘
```

- **Frontend:** React + TypeScript (dark "operations" UI, ~88 KB gzipped).
- **Backend:** Python / FastAPI, SQLite in WAL mode (handles four concurrent users
  and bursty event ingestion without a heavy database).
- **Deployment:** two Docker containers via Docker Compose, behind Caddy.
- **Design principle:** every optional piece (Semgrep, tshark, Suricata, a domain
  for HTTPS) degrades *gracefully*, the core app works without any of them.

---

## 4. What it can do (capabilities)

The app has **four workspaces** behind **one shared team login** (four people can be
signed in at once; optional "Player 1…Substitute" labels tag who did what).

### 🎯 Attack
- **Target registry** = the authorized scope. Recon against anything *not* in the
  registry is refused by the server.
- **Recon toolkit:** TCP connect, banner grab, HTTP header/technology fingerprint, all bounded (timeouts, no Internet-wide scanning).
- **Exploit knowledge base:** curated techniques (SQLi, command injection, SSTI,
  SSRF, etc.) with detection logic, preconditions, safe test procedures and mitigations.
- **Flag utility:** capture, de-duplicate, track accepted/rejected; a configurable
  submission adapter (off by default until the organizer's API is known).

### 🛡️ Defense (a standout feature)
- Paste source code → get a **structured security analysis in seconds**, with **no AI**.
- Covers Python, PHP, JavaScript/TypeScript, Java, C/C++, shell.
- Each finding shows: matched line(s), *why* it's dangerous, the detected input
  source, a **safe test**, a **language-specific patch**, a **regression test**,
  references and **honest limitations**.
- Confidence is graded (*Strongly supported / Potential / Needs context*). "No
  match" **never** claims the code is secure.

### ⚙️ Automation
- **Script library** with versioning, download, duplicate (6 real starter scripts loaded).
- **Deterministic utilities:** Base64 / URL / hex / hashes / JWT-decode (clearly
  marked *not verified*) / JSON / timestamp.
- **Service health monitoring** with real checks, latency and uptime history.

### 📡 Network / SOC: the headline feature
This is a **mini-SIEM** modeled on the offense-centric workflow of tools like QRadar.

- **Offense correlation:** thousands of automated attack requests collapse into a
  *single* offense. In testing, **500 SQL-injection requests became 1 offense** with
  counts, distinct-payload totals and a pointer to the strongest evidence.
- **Evidence-based outcomes**, the key differentiator:
  | Outcome | When |
  |---|---|
  | **CONFIRMED** | Direct, attributable proof (e.g. command output echoed back, instrumented proof of unauthorized action) |
  | **POSSIBLE** | Attack payload + a corroborating response anomaly (SQL error leak, reflected payload) |
  | **BLOCKED** | A control stopped it (403/429/WAF) |
  | **ATTEMPTED** | Pattern seen, outcome unknown |

  It will **never** call an attack successful just because the server returned 200
  or because an IDS fired. When it lacks the data to know, it says so.
- **Beginner-friendly offense page:** plain-language *What happened / Who / What they
  sent / Why flagged / Did it work / What to do*, then a **payload inspector**
  (raw / URL-decoded / hex, with suspicious parts highlighted).
- **Noise reduction:** confirmed and possibly-successful attacks surface first;
  routine blocked/attempted noise is collapsed but still searchable.
- **Data in:** Suricata EVE JSON (live sensors), structured access logs and **PCAP
  upload** (parsed with tshark).
- **Setup center:** copy-paste install/config guides for tcpdump, Suricata, TShark,
  Zeek and Tulip.

### 🔗 Shared across all of it
- **Findings** (shared notes/evidence) sync **live** across all four browsers, edit
  in one, it updates in the others, no refresh.
- An SOC offense can be **sent to Defense** as a finding in one click.

---

## 5. How powerful is it, really?

**Honest assessment: it is a genuinely useful, production-quality team tool for its
intended scope, not an enterprise SIEM and it doesn't pretend to be.**

Where it is strong:
- The **offense correlation + evidence-based "did it work?"** logic is the real
  intellectual value and it works end-to-end (verified in the browser and by an
  automated test suite). This is the hard part most homemade CTF dashboards skip.
- It is **honest by design**, it distinguishes "we detected an attempt" from "we
  have proof it worked," which is exactly what a stressed beginner needs.
- It is **lightweight and self-contained**: runs offline on a 4 GB box, no cloud
  services, no AI dependency, survives GitHub/Internet going down mid-competition.
- **Quality bar:** 40 automated backend tests pass, the frontend type-checks and
  builds, continuous integration is green and it's actually deployed and reachable.

Where it is modest (by deliberate choice):
- It handles *thousands* of events comfortably, not *millions*. It's sized for one
  team's traffic, not a SOC watching a whole enterprise.
- Detection is **signature/pattern-based**, which is predictable and explainable but
  not exhaustive, it finds known patterns, not novel zero-days.

---

## 6. Limitations (be aware of these)

- **No AI / no behavioral ML:** detection is deterministic rules and signatures. This
  is intentional (explainable, offline, no data leaves the box) but means coverage is
  bounded by the rules written.
- **Static code analysis flags patterns, not proven exploitability.** It can produce
  false positives and cannot guarantee it caught everything.
- **Encrypted traffic:** passive PCAP of HTTPS cannot reveal request/response bodies.
  Full payload visibility requires logging at the app or reverse-proxy layer.
- **Shared single account:** individual attribution is best-effort (session labels),
  not cryptographically guaranteed, acceptable for a trusted 4-person team.
- **Scale:** tuned for ~4 GB / 2 vCPU and one team's event volume, with retention
  caps. It is not built for long-term, high-volume log warehousing.
- **Currently HTTP-only in production** (no domain yet): credentials travel
  unencrypted. Must move to HTTPS or VPN before handling real flags.

---

## 7. What's lacking / not finished

These are **honestly incomplete or gated**, not hidden:

- **Controlled remote execution** (running scripts/exploits from the UI) is
  **disabled by default**, it needs a proper sandbox before it's safe to enable. The
  editor, library, downloads and local utilities all work; only server-side
  execution is off.
- **Scheduled/background jobs:** the data model exists; the scheduler itself isn't
  implemented yet.
- **Flag auto-submission:** the adapter is built but off until the competition's real
  submission API is configured (we never fake a competition integration).
- **Tulip integration** is file/deep-link based only (Tulip exposes no stable API).
- **Zeek** is documented in the setup guides but not yet parsed as a live feed.
- **Push-to-deploy (CI/CD):** the pipeline exists and CI is green, but the live VM was
  deployed from an uploaded snapshot, so auto-deploy needs a deploy key + the VM set
  up as a git checkout to be fully wired.

---

## 8. What can be improved (roadmap)

**Near-term, high value**
1. **HTTPS + a domain** (Caddy auto-issues the certificate), required before real use.
2. **Finish push-to-deploy:** deploy key on the VM so merging to `main` auto-ships.
3. **Expand the detection rule set** and add more Semgrep rules for the languages
   the team's services actually use.
4. **Live-tail / alerting:** in-app toast + optional webhook when a CONFIRMED or
   POSSIBLE offense appears.

**Medium-term**
5. **Safe execution sandbox** (gVisor / nsjail / isolated container) to turn on the
   controlled runner and the scheduler.
6. **Richer correlation:** join Suricata flow IDs with app logs and Zeek metadata for
   stronger "did it work?" evidence.
7. **Per-service dashboards** and a timeline view of an attack campaign.
8. **Retention/compression tuning** and disk-usage alerts for long competitions.

**Nice-to-have**
9. Keyboard-driven navigation and saved searches in the event explorer.
10. One-click evidence export (PDF/JSON) for post-competition write-ups.

---

## 9. Current deployment status

| Item | Status |
|---|---|
| Live URL | **http://20.189.71.166** (reachable, API + SPA returning 200) |
| Containers | backend (healthy) + Caddy web, Docker Compose on the Azure VM |
| Data persistence | SQLite + uploads in a Docker volume (survives redeploys) |
| Tests | 40 backend tests passing; CI green |
| Private repo | `171k/ad-command-center` (private, `main`) |
| HTTPS | ❌ not yet, needs a domain + port 443 |
| Remote execution | 🔒 intentionally disabled (no sandbox yet) |

---

## 10. The one-slide takeaway

> We have a **working, deployed, honestly-scoped** operations center for the team.
> Its real value is the **SIEM that groups attack floods into a handful of offenses
> and tells you, with evidence, which ones actually succeeded**, the thing that
> normally takes an experienced analyst. It runs offline on a cheap server with no
> AI. Before the competition we need to **(1) put it behind HTTPS/VPN** and
> **(2) load the competition's real targets and flag API.** Enabling in-app script
> execution is a deliberate later step that needs a security sandbox first.
