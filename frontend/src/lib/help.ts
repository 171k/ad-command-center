// Beginner-oriented "How to use" content, one entry per workspace.
// Shown in a slide-out drawer from the "How to use" button on each page.

export type HelpSection = { heading: string; ordered?: boolean; steps: string[] };
export type HelpDoc = { title: string; intro?: string; sections: HelpSection[]; tip?: string };

export const HELP: Record<string, HelpDoc> = {
  attack: {
    title: "Attack",
    intro:
      "Your offense cockpit. It organizes targets, recon and captured flags. It does NOT run exploits for you. Actual attacks run on your Kali box.",
    sections: [
      {
        heading: "Targets: define your scope first",
        ordered: true,
        steps: [
          "Click “Add target” and enter the name, host/IP, port and protocol.",
          "Set Owner: “ours” (a service you defend) or “opponent” (a box you attack).",
          "Tick “Authorized” only on opponent boxes the rules let you probe.",
          "Anything not registered here is refused by the server, so register before you touch it.",
        ],
      },
      {
        heading: "Recon: safe, light probing",
        steps: [
          "Pick a registered target from the dropdown.",
          "Run TCP connect, Banner grab or HTTP inspect, all bounded and timeout-limited.",
          "Heavy scanning (nmap, ffuf, dirb) still runs on Kali; this is just a quick first look.",
        ],
      },
      {
        heading: "Knowledge: the playbook",
        steps: [
          "Search common vulnerability classes (SQLi, command injection, SSTI…).",
          "Expand an entry for preconditions, a safe test and a copy-paste exploit template.",
          "Use this to learn WHAT to try when you're stuck.",
        ],
      },
      {
        heading: "Flags: track every capture",
        steps: [
          "Paste a captured flag and click Add. Duplicates are detected automatically.",
          "“Submit pending” pushes to the organizer API (currently OFF until configured).",
          "Until then, also submit flags on the official scoreboard yourself.",
        ],
      },
    ],
    tip: "Assign one teammate to own each opponent target so two people don't attack the same box and step on each other.",
  },

  defense: {
    title: "Defense",
    intro:
      "Find and fix vulnerabilities in YOUR own services. Everything is rule-based (no AI). A clean result means “nothing obvious found,” never “guaranteed safe.”",
    sections: [
      {
        heading: "Analyze: scan your code",
        ordered: true,
        steps: [
          "Paste source into the editor, or click Upload file to load one.",
          "Pick the language or leave it on Auto.",
          "Click Analyze. Two engines run together: the built-in curated rules and Semgrep.",
          "Each finding shows the line, the possible exploit, an example payload and how to patch it.",
        ],
      },
      {
        heading: "Rule library",
        steps: [
          "Browse every detection rule so you know exactly what is and isn't checked.",
        ],
      },
      {
        heading: "Saved",
        steps: ["Past analyses are kept here so you can re-open them during the match."],
      },
    ],
    tip: "After applying ANY patch, re-run the service health check. A broken service loses more points than an unpatched vulnerability.",
  },

  automation: {
    title: "Automation",
    intro: "Shared helpers for the whole team: scripts, encoders/decoders and a safe local runner.",
    sections: [
      {
        heading: "Scripts",
        steps: ["Store and version team scripts. Every save keeps a downloadable revision."],
      },
      {
        heading: "Utilities",
        steps: [
          "One-click encode/decode: base64, URL, hex, hashing, JWT decode, JSON, timestamps.",
          "Paste input, pick an operation, copy the result. Works fully offline.",
        ],
      },
      {
        heading: "Runner",
        steps: [
          "Runs a small set of SAFE, local-only tools (hash-id, dictionary check, wordlist, entropy) in a sandbox.",
          "It never touches opponent targets. Those stay manual on Kali.",
        ],
      },
      {
        heading: "Health",
        steps: ["Live up/down status of every service you registered."],
      },
    ],
    tip: "Reach for Utilities before searching for an online decoder. It's faster and keeps your data off the internet.",
  },

  soc: {
    title: "Network / SOC",
    intro:
      "See who is attacking you. It reads logs from your defended service, groups attacks into “offenses” and marks each CONFIRMED only when there's real proof.",
    sections: [
      {
        heading: "Setup: do this FIRST",
        steps: [
          "The SOC stays empty until a log source is wired up.",
          "Open the Setup tab and follow it to point your service's logs (Suricata EVE JSON or access logs) here.",
          "Do this before the match starts.",
        ],
      },
      {
        heading: "Dashboard",
        steps: ["At-a-glance traffic volume and offense counts."],
      },
      {
        heading: "Offenses",
        steps: [
          "Each row is a correlated attack campaign (e.g. an SQLi flood).",
          "Open one to see the evidence, add notes or send it straight to Defense as a finding.",
        ],
      },
      {
        heading: "Events & Sensors",
        steps: [
          "Events: the raw, normalized log stream with filters and a payload inspector.",
          "Sensors: register and name the log sources feeding the SOC.",
        ],
      },
    ],
    tip: "If the dashboard looks empty, nobody has connected a log source yet. Start on the Setup tab.",
  },

  pwn: {
    title: "Pwn Solver",
    intro:
      "Static-analysis helpers for binary exploitation challenges. It inspects binaries and does the byte-math; it does not auto-solve them.",
    sections: [
      {
        heading: "Binaries",
        ordered: true,
        steps: [
          "Upload an ELF challenge binary.",
          "Read checksec (NX / PIE / RELRO / canary) plus symbols, strings and sections.",
          "Search for ROP gadgets.",
          "Generate a pwntools template and save your exploit script per case.",
        ],
      },
      {
        heading: "Utilities",
        steps: [
          "Cyclic pattern generator + crash-offset finder (to locate the return address).",
          "Arch-aware pack/unpack: the common byte-math for buffer overflows.",
        ],
      },
    ],
    tip: "Run the actual exploit against the target on Kali, using the saved pwntools template as your starting script.",
  },

  tools: {
    title: "Tool Repository",
    intro:
      "Your team's private tool store, so you don't depend on GitHub or the internet during the match.",
    sections: [
      {
        heading: "If it's empty",
        steps: ["Click Seed to load the 16-tool curated catalog (names, licenses, install commands)."],
      },
      {
        heading: "Browse & install",
        steps: [
          "Search or filter by category. Each tool shows its license and a per-OS install command.",
          "Download an artifact. Every file is SHA-256 checksum-verified against tampering.",
        ],
      },
      {
        heading: "Offline bundle",
        steps: [
          "Click “Offline bundle” to export everything as one file for an air-gapped laptop.",
          "Install later from it with the included adtools CLI, no internet needed.",
        ],
      },
    ],
    tip: "Generate the Offline bundle before competition day, while you still have internet and can fetch binaries.",
  },

  findings: {
    title: "Findings",
    intro:
      "The team's shared log of everything you discover (vulns, exploits, notes), synced live across all four of you.",
    sections: [
      {
        heading: "Create",
        steps: ["Click “New finding” to log something. Everyone sees it instantly."],
      },
      {
        heading: "Triage",
        steps: [
          "Filter by status: open / investigating / resolved.",
          "Search by text to find a finding fast.",
        ],
      },
      {
        heading: "From the SOC",
        steps: ["SOC offenses can be pushed here as findings automatically, so attacks become to-dos."],
      },
    ],
    tip: "One finding = one issue. Include the service, the vulnerability and the fix so attackers and defenders stay in sync.",
  },
};
