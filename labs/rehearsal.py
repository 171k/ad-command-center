"""End-to-end A&D rehearsal against our own isolated lab service. No external
targets. Evidence is printed for each phase."""
import ast
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, "backend")
sys.path.insert(0, "labs")

import vuln_service  # noqa: E402
from app.analyzer import engine  # noqa: E402
from app import patching  # noqa: E402
from app.ops import generators  # noqa: E402
from app.soc import classify  # noqa: E402

PORT = 8077
print("=" * 70)
print("PHASE A - ATTACK (isolated local lab 127.0.0.1:%d)" % PORT)
srv = vuln_service.start(PORT)
BASE = f"http://127.0.0.1:{PORT}"

# RCE Script Generator produces a valid, editable script for the authorised target
payload = "0 UNION SELECT id, flag FROM secret"
gen = generators.rce_script({"protocol": "requests", "name": "lab-sqli", "host": "127.0.0.1",
                             "port": PORT, "path": "/item", "method": "GET",
                             "params": {"id": "{{PAYLOAD}}"}, "payload": payload,
                             "expected": "iHACK{"})
ast.parse(gen["script"])
print("  [A1] RCE script generated:", gen["filename"], "| parses: OK | contains payload:",
      payload in gen["script"])

# Controlled test against the lab (the generator's requests flow, done with stdlib here)
normal = urllib.request.urlopen(f"{BASE}/item?id=1", timeout=5).read().decode()
exploit_url = f"{BASE}/item?id=" + urllib.parse.quote(payload)
leaked = urllib.request.urlopen(exploit_url, timeout=5).read().decode()
print("  [A2] normal  /item?id=1 ->", normal[:60])
print("  [A3] exploit /item?id=<sqli> ->", leaked[:80])
flag = vuln_service.FLAG
print("  [A4] FLAG disclosed by exploit:", flag in leaked, "(evidence of successful controlled test)")

print("=" * 70)
print("PHASE B/C - CAPTURE / SOC (evidence-based classification)")
events = vuln_service.drain_events()
print("  [C1] service telemetry events captured:", len(events))
# The exploit request carries app_proof (flag disclosed); classify it.
proof_event = next((e for e in events if e.get("app_proof")), None)
if proof_event:
    verdict = classify.classify_offense([proof_event]) if hasattr(classify, "classify_offense") else None
    print("  [C2] app_proof present:", bool(proof_event.get("app_proof")))
    print("       proof:", proof_event["app_proof"][:80])
    if verdict:
        print("  [C3] SOC verdict:", verdict)
else:
    print("  [C2] no app_proof event found")

print("=" * 70)
print("PHASE D - DEFENSE (analyze -> finding -> patch diff -> validation)")
VULN = 'query = f"SELECT id, name FROM items WHERE id = {raw_id}"\nrows = db.execute(query).fetchall()'
PATCH = 'rows = db.execute("SELECT id, name FROM items WHERE id = ?", (raw_id,)).fetchall()'
res = engine.analyze(VULN, "python", use_semgrep=False)
sqli = [f for f in res["findings"] if "89" in (f.get("cwe") or "")]
print("  [D1] analyzer findings:", res["finding_count"], "| SQLi (CWE-89) detected:", bool(sqli))
if sqli:
    print("       finding:", sqli[0]["name"], "| line", sqli[0]["line"])
diff = patching.unified_diff(VULN, PATCH, "vuln_service.py")
stats = patching.diff_stats(VULN, PATCH)
print("  [D2] unified diff produced:", "+++ b/vuln_service.py" in diff, "| stats:", stats)
# status workflow (server-validated transitions)
p = {"security_status": "pending", "functional_status": "pending"}
chain = ["reviewed", "tested", "applied"]
cur = "suggested"
ok = True
for to in chain:
    err = patching.transition_error(cur, to, p)
    ok = ok and err is None
    cur = to
print("  [D3] suggested->reviewed->tested->applied all allowed:", ok)
print("  [D4] applied->verified BLOCKED without validations:",
      patching.transition_error("applied", "verified", p) is not None)
p["security_status"] = "pass"; p["functional_status"] = "pass"
print("  [D5] applied->verified ALLOWED once security+functional pass:",
      patching.transition_error("applied", "verified", p) is None)

print("=" * 70)
print("PHASE E - RECOVERY")
srv.shutdown()
print("  [E1] lab service stopped (simulating service restart)")
srv2 = vuln_service.start(PORT + 1)
health = urllib.request.urlopen(f"http://127.0.0.1:{PORT+1}/", timeout=5).read().decode()
print("  [E2] restarted on new port, health:", "demo-shop" in health)
print("  [E3] rollback reference pattern: 'docker tag <img>:prev <img>:latest && compose up -d --force-recreate' (guide)")
srv2.shutdown()
print("=" * 70)
print("REHEARSAL COMPLETE")
