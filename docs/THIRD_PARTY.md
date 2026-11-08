# Third-party tools & licenses

The objective is to combine proven tools with focused original engineering, not
to rewrite everything. This records what is reused, how and under what license.
Verify versions on your host; pin them in your environment.

## Runtime dependencies (bundled / installed)

| Component | Version (pinned) | License | How it is used |
|---|---|---|---|
| FastAPI | 0.115.6 | MIT | HTTP API framework |
| Uvicorn | 0.34.0 | BSD-3 | ASGI server |
| Pydantic | 2.10.4 | MIT | Request/response validation |
| argon2-cffi | 23.1.0 | MIT | Argon2id password hashing |
| httpx | 0.28.1 | BSD-3 | Outbound recon / health / flag submit |
| pyotp | 2.9.0 | MIT | Optional TOTP MFA |
| React | 18.3.1 | MIT | UI |
| Vite | 5.4.2 | MIT | Build tooling |
| Tailwind CSS | 3.4.10 | MIT | Styling |
| TanStack Query | 5.51.23 | MIT | Data fetching / cache |
| lucide-react | 0.427.0 | ISC | Icons |
| Caddy | 2.8 (image) | Apache-2.0 | Reverse proxy, auto-HTTPS |

## External tools (integrated by adapter, not vendored)

These are **not** bundled; the app calls them if present and degrades if not. We
did not fork or copy their source, we integrate via their documented interfaces.

| Tool | Role | Integration | License |
|---|---|---|---|
| **Semgrep** (CE) | Static analysis | Optional: `semgrep --json` over a temp file with local rules; merged into results | LGPL-2.1 (CLI) |
| **Suricata** | Network IDS | Primary SOC feed: we parse its **EVE JSON** output; no Suricata code embedded | GPL-2.0 |
| **TShark / Wireshark** | PCAP parsing | `tshark -r file -Y http.request -T fields …`; output normalized into events | GPL-2.0 |
| **Zeek** | Traffic metadata | Setup guidance only; optional collector feed | BSD-3 |
| **Tulip** (OpenAttackDefenseTools) | A/D traffic browser | Optional, file-based/deep-link workflow; **no invented API** | MIT |

Because Suricata/TShark/Zeek are invoked as separate processes (not linked), the
application code remains independent of their GPL terms; deploy them as the
distribution packages them. Semgrep is likewise invoked as a CLI.

## Original engineering (not reused)

- The unified operations UI and design system.
- The beginner-friendly SIEM: **offense correlation** (event-time windowed
  grouping, noise reduction, upgrade-on-stronger-evidence).
- **Evidence-based outcome classification** (CONFIRMED only from attributable
  application-level proof; never from an IDS hit or an HTTP status alone).
- Cross-workspace collaboration and shared findings with live sync.
- The deterministic analyzer's taint-proximity confidence scoring and curated
  multi-language rule base.

## Obligations

- Preserve license texts of any tool you redistribute (we redistribute none of
  the external IDS/parsers; they are installed from upstream packages).
- If you add code copied from a GPL project, that file inherits GPL, prefer the
  adapter pattern used here instead.
