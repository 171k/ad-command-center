# Competition-Readiness Audit (vNext)

Evidence-based review for iHack 2026 (Nov 17–18). **Verified** = exercised by an
automated test or a live check in this session. **Partial** = implemented but not
end-to-end verified here. **Blocked** = needs external infra/authorization.

Test evidence: `backend/tests/` (59 passing, 1 POSIX-only skipped on Windows CI runs it).

## Attack workspace
| Capability | Status | Evidence |
|---|---|---|
| Manage authorized targets (scope registry) | ✅ Verified | `test_api.test_services_scope_enforced` |
| Recon limited to allowlisted scope (reject others) | ✅ Verified | out-of-scope → 403 |
| Exploit knowledge base (techniques, mitigations) | ✅ Verified | `/api/attack/knowledge` |
| Flags: capture, dedup, status tracking | ✅ Verified | `test_api.test_flag_dedup` |
| Flag auto-submission to organizer API | ⚠️ Partial | adapter present, **off** until the real competition API is configured |
| "Successful exploitation evidence" without losing context | ✅ Verified (via SOC offenses + Findings) | offense→finding link |

## Defense workspace
| Capability | Status | Evidence |
|---|---|---|
| Identify vulnerabilities in pasted code (deterministic, no AI) | ✅ Verified | `test_analyzer.py` (SQLi/CMDi/XSS/SSTI/SSRF/…) |
| Code review via Semgrep + built-in rules, with file upload | ✅ Verified | `test_defense.py` (paste, upload, binary/empty reject, Semgrep enrichment) |
| Whole-project scan: upload a zip, extract safely (never executed), scan the tree | ✅ Verified | `test_defense_scan.py` (grouped-by-file, node_modules excluded, non-zip reject) |
| Exploit, example payload and patch per finding | ✅ Verified | `test_enrich.py` + `test_defense.py` |
| Confidence grading; "no match ≠ secure" | ✅ Verified | `test_analyzer` |
| Prepare patches + regression tests (per finding) | ✅ Verified | analyzer output includes patch + regression |
| Verify service functionality / recover from a bad patch | ⚠️ Partial | service **health checks** verify up/down; automated patch rollback is the operator's git workflow, not in-app |

## Automation workspace
| Capability | Status | Evidence |
|---|---|---|
| Deterministic utilities (base64/url/hex/hash/JWT-decode/JSON/timestamp) | ✅ Verified | `test_api.test_utils_operations` |
| Script library + revisions + download | ✅ Verified | `test_api.test_scripts_revisions` |
| Service health monitoring | ✅ Verified | services health endpoints |
| Sandboxed local-utility runner (hash-id, dict-check, wordlist, entropy) | ✅ Verified | `test_runner.py` (allowlist, timeout, mem cap, gated) |
| Scheduled jobs | ⛔ Incomplete (by design) | schema exists; scheduler not implemented; **disabled** |

## Network / SOC workspace
| Capability | Status | Evidence |
|---|---|---|
| Ingest EVE JSON / access logs / PCAP | ✅ Verified | `test_soc`, `test_api` (ingest, PCAP magic) |
| Correlate floods into offenses | ✅ Verified | 500 SQLi events → 1 offense (`test_soc`) |
| Evidence-based outcomes (CONFIRMED only from proof) | ✅ Verified | `test_soc`, `test_evidence`, `labs/` instrumented demo |
| Investigate offenses, notes, send-to-Defense | ✅ Verified | `test_api.test_send_offense_to_defense` |
| Export evidence | ⚠️ Partial | event export + payload inspector present; no single "case PDF" export |
| Clear demo/sample data | ✅ Verified | `test_api.test_clear_soc_data` |

## NEW: Tool Repository (P1)
| Capability | Status | Evidence |
|---|---|---|
| Catalog (16 tools, license/provenance/per-OS install) | ✅ Verified | `test_tools` |
| Upload artifact + SHA-256; TLS-authenticated download | ✅ Verified | `test_tools.test_upload_download_checksum` |
| Tamper detection | ✅ Verified | `test_tools.test_corrupt_artifact_detected` |
| Offline bundle export + offline install (no GitHub) | ✅ Verified | `test_tools.test_offline_bundle_install` |
| `adtools` CLI (online + offline) | ✅ Implemented | offline path tested; online path uses same endpoints |
| Hosted binary artifacts for every tool | ⚠️ Partial | mechanism works; **admin uploads the actual binaries** (license-reviewed) during prep |

## NEW: Pwn Solver (P2)
| Capability | Status | Evidence |
|---|---|---|
| Upload ELF; format/arch detection | ✅ Verified | `test_pwn.test_upload_analyze_and_persist` |
| checksec (NX/PIE/RELRO/canary/fortify/stripped) | ✅ Verified | `test_pwn` (full + weak crafted ELFs) |
| Name the vuln + approach (ret2win / ret2system / fmt) | ✅ Verified | `test_pwn_solver` (classify + compiled fixtures) |
| Auto-estimate overflow offset (capstone disasm) | ✅ Verified | `test_pwn_solver` (offset 56 on ret2win/ret2system) |
| Generate tailored pwntools script with offset + addresses | ✅ Verified | `test_pwn_solver` (script asserts) |
| Symbols / strings / sections | ✅ Verified | analysis output |
| Cyclic pattern + crash offset | ✅ Verified | `test_pwn.test_cyclic_and_find` |
| Pack/unpack (arch-aware) | ✅ Verified | `test_pwn.test_pack_unpack` |
| ROP gadget search | ✅ Verified | `test_pwn.test_find_gadgets` |
| pwntools template + saved scripts (persist restart) | ✅ Verified | persistence test |
| Crash/exploit **execution** | ⚠️ Partial (by design) | `scripts/pwn_sandbox.py` isolated LOCAL worker; server-side exec **gated off**; execution path verified only on Linux |
| readelf/objdump enrichment | ⚠️ Partial | used when binutils present; not required |

## Team use (concurrency)
- Per-user accounts (itik/mejik/gha/namia), shared operational data. ✅ Verified:
  `test_auth.test_two_users_concurrent_sessions`, `test_auth.test_password_change_is_per_user`.
- **Data-overwrite risk:** records are append/edit by id; there is **no optimistic-
  locking / conflict detection** on simultaneous edits of the *same* record, last
  write wins. Live SSE sync reduces blind overwrites but does not prevent them.
  ⚠️ Recommend: assign one owner per offense/finding during the match.

## Recovery
- Container restart preserves data (named volume). ✅ Verified in production
  (sentinel survived two deploys).
- DB restore from backup. ✅ `scripts/backup.sh` / `restore.sh` (volume tar).
- Loss of external connectivity (GitHub/Azure/internet). ✅ Verified: full
  in-process offline run; `docs/OFFLINE.md` procedure.
- GitHub/Tailscale down mid-match → **runtime unaffected** (only the deploy
  pipeline uses them). ✅

## Competition compliance
- No Claude/OpenAI/DeepSeek/other AI API required; no autonomous AI agent;
  all solver/analysis is deterministic. ✅ (no AI SDKs in `requirements.txt`).
- Potentially-restricted functions are **config-gated**: task runner, pwn exec,
  flag submission, scheduled jobs, all off by default.
- ⚠️ **For organizer approval:** confirm that hosting a tool repository, running a
  local pwn sandbox and active recon against opponent targets are permitted.
  Keep gated features off unless approved.
