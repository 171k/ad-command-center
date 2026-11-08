# Defense Scanner — Accuracy & Vulnerability Detection Upgrade

Branch: `feat/scanner-accuracy` (stacked on `fix/patch-editable` / PR #13,
because it builds on that branch's finding display-field work). Not merged, not
deployed.

This improves the existing scanner; it does not replace it. No AI, no network in
the scan path, source is never executed.

---

## 1. Root cause of the source-highlighting defect (Priority 1)

Reproduced with a **real Semgrep 1.184 run** against a local fixture (not the
organiser's source). Semgrep returned the matched line as the literal
placeholder string **`"requires login"`** in `extra.lines`, at `start.line = 55`:

```
Semgrep reported start.line = 55  extra.lines = 'requires login'
today's snippet entries: [{'line': 55, 'text': 'requires login', 'hit': True}]
  gutter shows 1 -> 'requires login'  (real source line is 55)
```

Three compounding defects:

1. **We trusted `extra.lines`.** Semgrep sometimes withholds the matched text
   and returns `"requires login"`; we put that straight into the snippet.
2. **The UI gutter numbered the snippet `i + 1`** (1..N), not the real source
   lines, so any finding appeared to "begin at line 1."
3. **No real per-line numbers, no surrounding context, no error path** — when a
   location could not be resolved, a line-1 snippet was shown instead of an
   explicit error.

### Fix

`engine.snippet_from_source()` slices evidence **straight from the real source**
by Semgrep's `start`/`end` line, with ±5 lines of context, true per-line numbers
and an accurate `hit` span. It rejects the `"requires login"` placeholder and
returns an explicit `snippet_error` for out-of-range locations instead of
fabricating line 1. Findings now carry `end_line`, `start_col`/`end_col` and
`rule_source`; the snippet schema (`{n, text, hit}`) is unified across built-in
and Semgrep. The frontend `CodeBlock` renders true source line numbers; each
finding shows `file:line`, the detecting rule, and a source-location error when
unresolved.

Verified end-to-end (real Semgrep): the CWE-22 finding at `docs.js:55` now
highlights the actual `fs.readFileSync(...)` line with correct numbering and
context — no `"requires login"`, no line-1.

---

## 2. Targeted JavaScript / Node.js detection (Priority 2)

New `semgrep_rules/nextjs.yml` (6 rules), enrichment for the new CWEs, and
`--no-git-ignore` so extracted trees always scan:

| Rule | CWE | Notes |
|---|---|---|
| `adcc-js-req-input-to-fs-path` | 22 | Taint: request input → fs/path sink. Follows intermediate vars, the helper call and the string-vs-array normalisation (dup-param type confusion). Sanitizers: `path.basename`, canonical `path.relative` containment, `typeof === "string"` guard. |
| `adcc-js-hardcoded-hmac-secret` | 321 | Literal or const-propagated HMAC key. |
| `adcc-js-non-constant-time-mac-compare` | 208 | `==`/`===` on a MAC/signature. |
| `adcc-js-secret-in-server-props` | 200 | Secret returned from `getServerSideProps`. |
| `adcc-js-next-public-secret-env` | 200 | `NEXT_PUBLIC_*` secret inlined into the client bundle. |
| `adcc-js-trust-client-role` | 285 | Role/privilege taken from request body/query (incl. destructuring). |

CWE enrichment added for **200, 208, 285, 321, 1286** (name + exploit + payload +
patch). Duplicate-parameter type confusion (CWE-1286) is explained in the
path-traversal finding and enrichment rather than as a noisy standalone rule.

---

## 3. Evidence-based correlation (Priority 3)

`analyzer/correlate.py` links findings **only** on concrete evidence:

- a shared security-relevant identifier present in both findings' evidence, or
- a source import edge between their files.

Connected components form groups. A conservative chain label ("…compromising the
first may enable the second…") is used **only** when an integrity/secret weakness
and an access-control weakness co-occur *with* shared evidence. It never hardcodes
a chain, never claims exploitability, and keeps unrelated findings separate.
Rendered as a "Related findings" panel with the exact evidence shown.

---

## 4–5. Finding quality & patch integration (Priorities 4–5)

Each finding now carries: vulnerability name, CWE, severity/confidence, true
file+lines, the matched expression, why-dangerous, preconditions, remediation,
regression test, **detecting rule source**, and limitations — plus a "how to fix"
CWE link and any CVE links. "Save as patch" seeds the existing Patch Diff &
History workflow (prose guidance → notes, actual code → the editable diff),
reusing the lifecycle and optimistic lock; Verified still requires both security
and functional validation.

---

## 6. Known-CVE detection foundation (Priority 6) — partially delivered

`analyzer/cve.py`, kept distinct from code-level CWE findings:

- **Inventory** from `package-lock.json` (v1/v2/v3), `requirements*.txt`,
  `composer.lock`, `go.mod`, and runtime markers (`Dockerfile FROM <img>:<tag>`).
- **Matching** via per-ecosystem version ranges → CVE id, component, installed
  version, fixed version, severity, source, confidence, remediation.
- **Advisories** load from a small, clearly-labelled vendored seed **plus** an
  out-of-band importer dir (`ADCC_ADVISORY_DIR`). No network in the scan path.

**Honesty rules enforced:** unknown version → `undetermined` (never
vulnerable/safe); runtime matches flagged *verify vendor backport*; no runtime
inventory → explicit limitation that runtime (e.g. PHP) status cannot be
determined from application source alone; presence never implies exploitation.

**Deferred (needs your decision):** a complete offline advisory database. The
earlier Trivy install was sandbox-blocked; options are (a) a CI-validated
importer that vendors an OSV/Trivy export into the image, or (b) grant a local
install. **PHP2Shell / 2026 PHP runtime CVEs are intentionally NOT hardcoded** —
I will not assert unverified 2026 identifiers/ranges; they require the importer
plus a supplied runtime/container inventory, at which point the existing matcher
handles them.

---

## 7. Benchmarks & results (Priority 7)

Fixtures in `tests/fixtures/benchmarks/`: a minimal **Array Escape reproduction**
(hand-written from the public writeup — **not** the organiser's source; the
original has not been re-tested here) and a **secure counterpart**.

Real Semgrep 1.184 over the full bundled ruleset, through the real
`analyze_tree` pipeline:

| Fixture | Findings | CWEs | Related groups |
|---|---|---|---|
| Array Escape (vuln) | 7 | 22, 200, 208, 285, 321, 798 | 1 (shared `SIGNING_SECRET` + imports) |
| Secure counterpart | **0** | — | 0 |

- **Weakness coverage (vuln):** exposed signing secret ✓ (200/321/798),
  auth-token weakness ✓ (208/285), path traversal ✓ (22), dup-param confusion ✓
  (explained on the path finding). **Missed:** none of the four classes.
- **Source-location accuracy:** every finding's highlighted line matches the
  real source line and text (e.g. `docs.js:55` → the actual `readFileSync`).
- **False positives:** 0 on the secure fixture (sanitizers recognise the
  canonical-containment idiom and the string-type guard).

Automated tests: `test_snippet_location.py`, `test_correlate.py`, `test_cve.py`
(run everywhere), and `test_scanner_benchmark.py` (runs the real pipeline, skips
where Semgrep is absent — e.g. local Windows — and runs in CI).

---

## 8. Security, offline use, resources (Priority 8)

Unchanged and preserved: auth, HTTPS, Tailscale deploy, GitHub Actions CI,
persistent SQLite, patch history, other workspaces. The scanner never executes
uploaded code; extraction keeps the existing zip-slip / size / count / symlink
guards; no package installs during a scan; advisories are read-only from a
pre-populated dir. Resource impact is marginal (static parsing + one extra
Semgrep ruleset file); no new runtime services.

## Test evidence

- Backend: full `pytest` suite green (CVE/correlation/snippet added), `ruff`
  clean.
- Frontend: `tsc --noEmit` clean, `vite build` clean.
- Real Semgrep 1.184 validation of rules, source-location fix, pipeline,
  correlation and the no-false-positive requirement (above).

## Remaining limitations

- Full offline CVE database integration is deferred (decision needed, §6).
- CVE version comparison is numeric and ignores pre-release/epoch edge cases.
- Correlation is intra-project and evidence-based; it suggests, it does not prove
  exploitability.
- The Array Escape benchmark is a reproduction, not the organiser's source.

## Clear separation

Code-level CWE findings (from source patterns/taint) and known dependency/runtime
CVE findings are produced and labelled separately, and unified in one Defense
report. The new rules are written to generalise (taint + sanitizers, framework
boundaries), not to fit Array Escape alone; the secure fixture confirms they do
not simply flag every query parameter or path call.
