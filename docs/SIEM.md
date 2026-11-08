# SIEM: detection, correlation & outcome evidence

The SOC is built to answer, for a beginner, in order:
*Is someone attacking us? Which attacks might succeed? Which succeeded? What did
they send? What should we do?* It prioritizes meaningful offenses over raw volume.

## 1. Ingestion & normalization

Inputs: Suricata **EVE JSON** (`alert`, `http`, `flow`, `fileinfo`), structured
HTTP **access logs** and **PCAP** (HTTP via tshark). Each record is normalized
(`app/soc/normalize.py`) into one internal event schema with:

- connection 5-tuple, flow/transaction IDs, HTTP method/URL/status/host,
- a bounded, escaped **payload** (+ original base64 when present),
- a deterministic **technique** (`classify_technique`) from signatures + decoded
  payload (sql_injection, command_injection, path_traversal, xss, ssti, ssrf,
  lfi_rfi, deserialization, scanner, …),
- a **fingerprint** that collapses variable parts (numbers, quotes, long hex) so
  automated bursts of one kind map together.

Malformed records are skipped; timestamps are canonicalized to SQLite format so
replayed/historical captures correlate correctly (not by wall-clock).

## 2. Offense correlation (`app/soc/correlate.py`)

Events are grouped into **offenses** by
`(technique, dest_ip, dest_port, src_ip)` within a sliding
**correlation window** (`ADCC_CORRELATION_WINDOW_SECONDS`, default 600s), measured
against the *event's own timestamp*.

- 10,000 automated SQLi attempts against one service ⇒ **one** offense with
  `event_count`, `distinct_payloads`, first/last seen and a pointer to the
  **strongest-evidence** event, not 10,000 rows.
- Different techniques from the same source are **not** merged.
- A later, stronger event **upgrades** the existing offense (and reopens a
  resolved/suppressed one) instead of spawning a redundant offense. A single
  significant success stays discoverable even after thousands of failures.

## 3. Outcome classification (`app/soc/classify.py`)

Deliberately conservative. Each outcome carries a transparent evidence list.

| Outcome | Requires |
|---|---|
| **CONFIRMED** | Direct, attributable application-level proof tied to the request: an instrumented service recording an unauthorized action, a verified flag read or a command-output marker echoed in the response. **Never** from an IDS signature, a 200 or a 500 alone. |
| **POSSIBLE** | A suspicious exploit payload **plus** a corroborating response anomaly: SQL-error leakage, a reflected XSS payload, a template-evaluation result (`{{7*7}}`→`49`) or a 500 with an injection payload (marked "suggestive, not proof"). |
| **BLOCKED** | Evidence a control stopped it (403/406/429, WAF `action=blocked`) with no contradictory success evidence. |
| **ATTEMPTED / UNKNOWN** | An attack pattern was seen but the outcome cannot be determined. |

Explicitly **not** done: "200 ⇒ success", "IDS hit ⇒ compromise", "500 ⇒ failed".
When telemetry is missing, the UI says so rather than guessing.

## 4. Noise reduction

The default offense list prioritizes **confirmed → possible → other severe** and
collapses suppressed and routine blocked/attempted-low offenses. Everything stays
searchable via a toggle and the Event Explorer. Newly observed techniques and
upgrade-worthy evidence are never silenced.

## 5. Evidence & payload inspection

The offense detail page leads with plain language (what happened / who / what they
sent / why flagged / did it work / what to do), then the strongest request with a
**payload inspector** (raw / URL-decoded / hex, suspicious substrings highlighted).
Payloads are shown as escaped text, never executed; "Payload unavailable" is shown
honestly when telemetry lacks the bytes; truncation is flagged.

## 6. Correlation sources

Suricata `flow_id` / HTTP `tx_id` are retained to correlate alerts with HTTP
metadata. Access logs and PCAP contribute request/response detail. Each source's
contribution is documented; the system does not assume correlation it cannot support.

## 7. Storage & performance (4 GB VPS)

Batched writes under one transaction, indexed event fields, aggregated offense
counters, bounded payload display, retention by age and max-event count
(`ADCC_MAX_EVENTS`, `ADCC_EVENT_RETENTION_DAYS`) and an ingest cap
(`ADCC_INGEST_QUEUE_MAX`). Heavy packet parsing (tshark) runs out-of-process. The
system indicates when evidence is truncated or expired rather than claiming full
visibility.

## Verifying it yourself

`backend/tests/test_soc.py` demonstrates: 500 SQLi events → one offense; CONFIRMED
only from proof/command-output; POSSIBLE from a SQL error; BLOCKED; "200 alone is
not success"; upgrade preserves the group; distinct techniques not merged.
`python -m app.admin demo-data` loads a labeled mixed scenario to explore in the UI.
