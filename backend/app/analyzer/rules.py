"""Curated, deterministic vulnerability rules.

These are NOT AI. Each rule is an explicit signature with:
  - a sink pattern (regex) that flags a dangerous construct,
  - optional taint-source hints that, when present near the sink, raise
    confidence from "potential" toward "strong",
  - beginner-readable explanation, preconditions, a safe test procedure,
  - a language-specific remediation and regression test,
  - documentation references and honest limitations.

Confidence is deterministic (see engine.py):
  strong         sink + a corroborating taint source reaches it
  potential      sink matched, unclear whether input is attacker-controlled
  needs_context  suspicious but one line is insufficient to judge
A rule NOT matching never implies the code is safe.
"""
from __future__ import annotations

from dataclasses import dataclass, field


# Common taint-source tokens by language family. Presence near a sink suggests
# attacker-controlled input flows into it. Deliberately conservative.
TAINT_SOURCES = {
    "python": [
        r"request\.(args|form|values|json|data|cookies|headers|files)",
        r"\binput\s*\(",
        r"sys\.argv", r"os\.environ", r"\.get_json\(",
        r"flask\.request", r"\bquery_params\b", r"\.read\(\)",
    ],
    "php": [r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)", r"php://input", r"file_get_contents\(\s*['\"]php://input"],
    "javascript": [
        r"req\.(query|params|body|headers|cookies)", r"location\.(search|hash|href)",
        r"window\.name", r"document\.(URL|cookie|referrer)", r"process\.argv",
        r"\.searchParams", r"event\.data",
    ],
    "java": [
        r"request\.getParameter", r"request\.getHeader", r"request\.getQueryString",
        r"getParameterValues", r"System\.getenv", r"args\[",
    ],
    "c": [r"\bargv\b", r"\bgets\b", r"\bscanf\b", r"\bgetenv\b", r"\bread\b", r"\brecv\b"],
    "cpp": [r"\bargv\b", r"std::cin", r"\bgetenv\b", r"\brecv\b"],
    "shell": [r"\$1\b", r"\$\{?[0-9]", r"\$@", r"\$\*", r"\bread\s+\w"],
}
# language aliases
LANG_ALIASES = {
    "ts": "javascript", "typescript": "javascript", "js": "javascript",
    "node": "javascript", "py": "python", "c++": "cpp", "cc": "cpp",
    "h": "c", "hpp": "cpp", "bash": "shell", "sh": "shell",
}


@dataclass
class Rule:
    id: str
    name: str
    cwe: str
    languages: list[str]
    sink: str                      # regex (multiline, case-insensitive off unless noted)
    description: str               # beginner-friendly
    why: str                       # why dangerous
    preconditions: str
    test_procedure: str
    exploit_template: str          # authorized verification template (not auto-run)
    remediation: dict              # {lang: code}
    why_patch_works: str
    regression_test: dict          # {lang: code}
    references: list[str]
    limitations: str
    base_confidence: str = "potential"   # potential | needs_context
    flags: int = 0                 # re flags
    safe_markers: list[str] = field(default_factory=list)  # nearby => likely safe


# A focused, tested set. Each has been exercised by backend/tests/test_analyzer.py.
RULES: list[Rule] = [
    # ---------------- SQL injection ----------------
    Rule(
        id="py-sql-fstring",
        name="SQL query built with string formatting",
        cwe="CWE-89",
        languages=["python"],
        sink=r"(execute|executemany)\s*\(\s*(f?['\"].*?(%s?|\{|\+|\.format).*?['\"]|[^,)]*%[^,)]*|[^,)]*\+[^,)]*)\)",
        description="A database query is assembled by concatenating or formatting strings instead of using bound parameters.",
        why="If any part of the string comes from user input, an attacker can change the meaning of the SQL and read or modify data they should not reach.",
        preconditions="Part of the concatenated/formatted string is derived from request input.",
        test_procedure="In an authorized test DB, send a value like `' OR '1'='1` in the relevant field and observe whether extra rows are returned.",
        exploit_template="# Authorized test only — point at your own lab service\nparam = \"' OR '1'='1' -- \"\n# GET /item?id=<param>",
        remediation={"python": "cur.execute(\"SELECT * FROM items WHERE id = ?\", (item_id,))"},
        why_patch_works="Parameter binding sends the value separately from the SQL text, so it can never be parsed as query structure.",
        regression_test={"python": "def test_sqli_blocked(client):\n    r = client.get(\"/item\", params={\"id\": \"' OR '1'='1\"})\n    assert r.status_code in (400, 404)  # not a full table dump"},
        references=["https://cwe.mitre.org/data/definitions/89.html", "https://owasp.org/www-community/attacks/SQL_Injection"],
        limitations="Flags string-built queries; cannot prove the input is attacker-reachable without seeing the call site.",
    ),
    Rule(
        id="py-sql-string-concat",
        name="SQL string assembled with concatenation/format",
        cwe="CWE-89",
        languages=["python"],
        sink=r"['\"]\s*(SELECT|INSERT|UPDATE|DELETE|DROP)\b[^'\"]*['\"]\s*(\+|%|\.format|$)|f['\"][^'\"]*\b(SELECT|INSERT|UPDATE|DELETE)\b[^'\"]*\{",
        description="A SQL statement is built by concatenating or formatting strings (often then passed to execute()).",
        why="If the concatenated value is user input, the query structure can be altered — classic SQL injection — even when the execute() call itself looks innocent.",
        preconditions="A concatenated/interpolated fragment carries user input.",
        test_procedure="In an authorized test DB, inject `' OR '1'='1` into the relevant field and observe extra rows.",
        exploit_template="# id=' OR '1'='1' -- ",
        remediation={"python": "cur.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))"},
        why_patch_works="Parameter binding keeps the value out of the SQL text so it cannot change the query.",
        regression_test={"python": "def test_sqli(client):\n    r = client.get('/item', params={'id': \"' OR '1'='1\"})\n    assert r.status_code in (400, 404)"},
        references=["https://cwe.mitre.org/data/definitions/89.html"],
        limitations="Flags SQL-shaped strings built dynamically; taint of the fragment is confirmed only when a source is nearby.",
    ),
    Rule(
        id="php-sql-concat",
        name="SQL query concatenates request data",
        cwe="CWE-89",
        languages=["php"],
        sink=r"(mysqli_query|->query|->exec|pg_query)\s*\(.*(\$_(GET|POST|REQUEST)|\.\s*\$)",
        description="A SQL query string includes request superglobals or concatenated variables directly.",
        why="Attacker-controlled input becomes part of the SQL command, enabling injection.",
        preconditions="Concatenated variable carries user input.",
        test_procedure="Submit `' OR '1'='1` in an authorized lab and watch for abnormal result sets.",
        exploit_template="// Authorized lab only\n// id=1' OR '1'='1' -- ",
        remediation={"php": "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n$stmt->execute([$id]);"},
        why_patch_works="Prepared statements separate code from data; bound values are never parsed as SQL.",
        regression_test={"php": "// assert prepared statement is used; injection returns no extra rows"},
        references=["https://cwe.mitre.org/data/definitions/89.html"],
        limitations="Static match; call-site reachability not proven.",
    ),
    Rule(
        id="java-sql-concat",
        name="SQL built with string concatenation (Statement)",
        cwe="CWE-89",
        languages=["java"],
        sink=r"(createStatement\(\)|Statement\s+\w+).*?\.(executeQuery|executeUpdate|execute)\s*\(.*\+",
        description="A java.sql.Statement runs SQL assembled with '+' concatenation.",
        why="Concatenated user input can alter the query; PreparedStatement is required.",
        preconditions="Concatenated value is user-supplied.",
        test_procedure="Authorized lab: inject `' OR '1'='1` and observe.",
        exploit_template="// id=1' OR '1'='1' -- ",
        remediation={"java": "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM u WHERE id = ?\");\nps.setInt(1, id);"},
        why_patch_works="PreparedStatement binds parameters out-of-band from the SQL text.",
        regression_test={"java": "// assert PreparedStatement used and injection yields no extra rows"},
        references=["https://cwe.mitre.org/data/definitions/89.html"],
        limitations="Does not track whether the concatenated value is tainted.",
    ),
    # ---------------- Command injection ----------------
    Rule(
        id="py-cmd-shell-true",
        name="subprocess with shell=True",
        cwe="CWE-78",
        languages=["python"],
        sink=r"(subprocess\.(run|call|Popen|check_output)|os\.popen)\s*\([^)]*shell\s*=\s*True",
        description="An OS command is executed through the shell (shell=True), so shell metacharacters are interpreted.",
        why="If any part of the command string is user input, characters like ; | $() `` let the attacker run arbitrary commands.",
        preconditions="The command string includes attacker-influenced input.",
        test_procedure="Authorized lab: supply `; id` (or `& whoami`) and check whether a second command runs.",
        exploit_template="# Authorized lab only\npayload = '127.0.0.1; id'",
        remediation={"python": "subprocess.run([\"ping\", \"-c\", \"1\", host], shell=False, timeout=5)"},
        why_patch_works="Passing an argument list with shell=False means the OS executes exactly one program with literal arguments — no shell parsing.",
        regression_test={"python": "def test_cmdi(client):\n    r = client.post('/ping', json={'host': '127.0.0.1; id'})\n    assert 'uid=' not in r.text"},
        references=["https://cwe.mitre.org/data/definitions/78.html", "https://docs.python.org/3/library/subprocess.html#security-considerations"],
        limitations="shell=True is sometimes used with fully static strings (lower risk); confirm the input source.",
        base_confidence="potential",
    ),
    Rule(
        id="js-child-exec",
        name="child_process.exec with a command string",
        cwe="CWE-78",
        languages=["javascript"],
        sink=r"(child_process\.)?\bexec(Sync)?\s*\(\s*[`'\"].*?\$\{|(child_process\.)?\bexec(Sync)?\s*\([^)]*\+",
        description="exec() runs a command through /bin/sh, interpreting shell metacharacters in interpolated input.",
        why="Template or concatenated user input can inject extra shell commands.",
        preconditions="Interpolated value is user-controlled.",
        test_procedure="Authorized lab: send `127.0.0.1; id` and observe output.",
        exploit_template="// host = '127.0.0.1; id'",
        remediation={"javascript": "const { execFile } = require('node:child_process');\nexecFile('ping', ['-c', '1', host], { timeout: 5000 }, cb);"},
        why_patch_works="execFile passes arguments as an array to one binary without a shell.",
        regression_test={"javascript": "// assert execFile used; injected ';' does not spawn a second process"},
        references=["https://cwe.mitre.org/data/definitions/78.html", "https://nodejs.org/api/child_process.html"],
        limitations="execFile/spawn with an array is safe; this flags exec() with dynamic strings.",
    ),
    Rule(
        id="c-system",
        name="system()/popen() with a constructed command",
        cwe="CWE-78",
        languages=["c", "cpp"],
        sink=r"\b(system|popen)\s*\(",
        description="system()/popen() invoke the shell; if the command string includes external input it enables command injection.",
        why="Shell metacharacters in input run attacker commands with the process's privileges.",
        preconditions="Command string derives from argv, network, or environment.",
        test_procedure="Authorized lab: provide `; id` style input and observe.",
        exploit_template="/* arg = \"x; id\" */",
        remediation={"c": "/* Use execvp with an argument vector, no shell: */\nchar *av[] = {\"ping\", \"-c\", \"1\", host, NULL};\nexecvp(av[0], av);"},
        why_patch_works="exec*-family calls run a program directly with discrete arguments, bypassing the shell parser.",
        regression_test={"c": "/* assert no /bin/sh is spawned for user input */"},
        references=["https://cwe.mitre.org/data/definitions/78.html"],
        limitations="system() with a compile-time-constant string is lower risk; verify the argument origin.",
        base_confidence="needs_context",
    ),
    # ---------------- Path traversal / LFI ----------------
    Rule(
        id="py-path-join-input",
        name="Filesystem path built from input",
        cwe="CWE-22",
        languages=["python"],
        sink=r"(open|os\.path\.join|send_file|Path)\s*\([^)]*(request\.|input\(|argv|\.get_json)",
        description="A file path is assembled from request input without normalization or allowlisting.",
        why="Input like ../../etc/passwd escapes the intended directory and reads arbitrary files.",
        preconditions="The path component is user-controlled and not validated.",
        test_procedure="Authorized lab: request `?file=../../etc/passwd` and check whether out-of-scope files are served.",
        exploit_template="# file=../../../../etc/passwd",
        remediation={"python": "import os\nbase = '/srv/files'\np = os.path.realpath(os.path.join(base, name))\nif not p.startswith(base + os.sep):\n    abort(403)"},
        why_patch_works="Resolving the real path and checking it stays under the base directory rejects traversal sequences.",
        regression_test={"python": "def test_traversal(client):\n    r = client.get('/f', params={'file': '../../etc/passwd'})\n    assert r.status_code == 403"},
        references=["https://cwe.mitre.org/data/definitions/22.html", "https://owasp.org/www-community/attacks/Path_Traversal"],
        limitations="Flags path+input; cannot confirm absence of validation elsewhere.",
    ),
    Rule(
        id="php-include-input",
        name="Dynamic include/require from input (LFI/RFI)",
        cwe="CWE-98",
        languages=["php"],
        sink=r"(include|include_once|require|require_once)\s*\(?\s*\$_(GET|POST|REQUEST)",
        description="A file is included based on request input, enabling local/remote file inclusion.",
        why="Attackers can include arbitrary local files (or remote URLs if allow_url_include is on) and execute code.",
        preconditions="Include target is user-controlled.",
        test_procedure="Authorized lab: `?page=../../../../etc/passwd` and observe.",
        exploit_template="// page=php://filter/convert.base64-encode/resource=index",
        remediation={"php": "$allowed = ['home' => 'home.php', 'about' => 'about.php'];\n$page = $allowed[$_GET['page']] ?? 'home.php';\ninclude $page;"},
        why_patch_works="An allowlist map means only known files can ever be included; input selects a key, not a path.",
        regression_test={"php": "// assert unknown keys fall back to a default and never include arbitrary paths"},
        references=["https://cwe.mitre.org/data/definitions/98.html"],
        limitations="Static match of include + superglobal.",
        base_confidence="potential",
    ),
    # ---------------- SSTI ----------------
    Rule(
        id="py-jinja-render-string",
        name="Template rendered from a string with input (SSTI)",
        cwe="CWE-1336",
        languages=["python"],
        sink=r"(render_template_string|Template\s*\()\s*[^)]*(request\.|input\(|%|\+|\.format|f['\"])",
        description="A template is built from a dynamic string that includes user input instead of a fixed template file.",
        why="Jinja/Mako evaluate expressions; attacker input in the template body can execute Python and reach OS commands.",
        preconditions="User input is concatenated/formatted into the template source.",
        test_procedure="Authorized lab: send `{{7*7}}`; if the response contains 49 the template evaluates input.",
        exploit_template="# name={{7*7}}  then  {{config}} / {{''.__class__...}}",
        remediation={"python": "return render_template('hello.html', name=name)  # fixed template, data passed as context"},
        why_patch_works="A fixed template file treats `name` as data for auto-escaped output, never as template code.",
        regression_test={"python": "def test_ssti(client):\n    r = client.get('/hello', params={'name': '{{7*7}}'})\n    assert '49' not in r.text"},
        references=["https://cwe.mitre.org/data/definitions/1336.html", "https://owasp.org/www-community/attacks/Server_Side_Template_Injection"],
        limitations="render_template_string with static content is safe; the input marker reduces false positives.",
    ),
    # ---------------- XSS ----------------
    Rule(
        id="js-innerhtml",
        name="Untrusted data assigned to innerHTML",
        cwe="CWE-79",
        languages=["javascript"],
        sink=r"\.innerHTML\s*=\s*[^;]*(location|req\.|params|query|input|value|data)",
        description="HTML is set from dynamic data via innerHTML, which parses and runs markup.",
        why="If the data contains attacker HTML/script it executes in the victim's browser (DOM XSS).",
        preconditions="The assigned value is attacker-influenced.",
        test_procedure="Authorized lab: inject `<img src=x onerror=alert(1)>` and see if it fires.",
        exploit_template="// q=<img src=x onerror=alert(1)>",
        remediation={"javascript": "el.textContent = value;  // or sanitize with DOMPurify.sanitize(value)"},
        why_patch_works="textContent inserts text literally; the browser never parses it as HTML.",
        regression_test={"javascript": "// assert injected <script>/onerror does not execute"},
        references=["https://cwe.mitre.org/data/definitions/79.html", "https://owasp.org/www-community/attacks/xss/"],
        limitations="Static assignments of constant HTML are safe; the dynamic marker narrows matches.",
    ),
    Rule(
        id="php-echo-input",
        name="Request data echoed without encoding (reflected XSS)",
        cwe="CWE-79",
        languages=["php"],
        sink=r"\becho\b[^;]*\$_(GET|POST|REQUEST|COOKIE)",
        description="User input is echoed into the page without HTML-encoding.",
        why="Reflected markup/script runs in the victim's browser.",
        preconditions="Output lands in an HTML context.",
        test_procedure="Authorized lab: `?q=<script>alert(1)</script>` and observe.",
        exploit_template="// q=<script>alert(1)</script>",
        remediation={"php": "echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');"},
        why_patch_works="htmlspecialchars encodes <, >, &, and quotes so the browser renders them as text.",
        regression_test={"php": "// assert output contains &lt;script&gt; not <script>"},
        references=["https://cwe.mitre.org/data/definitions/79.html"],
        limitations="Context matters (HTML vs attribute vs JS); encode for the right context.",
    ),
    # ---------------- SSRF ----------------
    Rule(
        id="py-requests-input-url",
        name="Outbound request to a URL from input (SSRF)",
        cwe="CWE-918",
        languages=["python"],
        sink=r"(requests\.(get|post|put|head)|urllib\.request\.urlopen|httpx\.(get|post))\s*\([^)]*(request\.|input\(|\.get_json|argv)",
        description="The server fetches a URL supplied by the user.",
        why="Attackers can target internal services (169.254.169.254 metadata, localhost admin ports) the server can reach.",
        preconditions="The URL is user-controlled and not restricted to an allowlist.",
        test_procedure="Authorized lab: point the URL at an internal address you control and confirm it is reached.",
        exploit_template="# url=http://169.254.169.254/latest/meta-data/",
        remediation={"python": "from urllib.parse import urlparse\nhost = urlparse(url).hostname\nif host not in ALLOWED_HOSTS:\n    abort(400)\n# plus: resolve DNS and reject private/link-local ranges"},
        why_patch_works="An allowlist of destination hosts (and blocking private ranges) prevents reaching internal targets.",
        regression_test={"python": "def test_ssrf(client):\n    r = client.post('/fetch', json={'url': 'http://169.254.169.254/'})\n    assert r.status_code == 400"},
        references=["https://cwe.mitre.org/data/definitions/918.html", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
        limitations="Allowlist presence cannot be confirmed statically; treat as potential.",
    ),
    # ---------------- Unsafe deserialization ----------------
    Rule(
        id="py-pickle-loads",
        name="pickle/yaml.load on untrusted data",
        cwe="CWE-502",
        languages=["python"],
        sink=r"(pickle\.loads?|yaml\.load)\s*\(",
        description="Deserializing with pickle or unsafe yaml.load can execute arbitrary code embedded in the data.",
        why="These formats can reconstruct arbitrary objects and call code during loading.",
        preconditions="The serialized bytes come from an untrusted source.",
        test_procedure="Authorized lab: craft a benign object whose __reduce__ touches a sentinel file; confirm it is invoked.",
        exploit_template="# Benign PoC marker only — never a real payload",
        remediation={"python": "import json\ndata = json.loads(raw)  # or yaml.safe_load(raw)"},
        why_patch_works="JSON / yaml.safe_load only build plain data types and never invoke object constructors or code.",
        regression_test={"python": "def test_deser():\n    assert deserialize(b'...') does not execute code"},
        references=["https://cwe.mitre.org/data/definitions/502.html", "https://docs.python.org/3/library/pickle.html"],
        limitations="pickle on fully trusted local data is acceptable; flag when the source is external.",
    ),
    Rule(
        id="java-objectinputstream",
        name="Java native deserialization (ObjectInputStream)",
        cwe="CWE-502",
        languages=["java"],
        sink=r"new\s+ObjectInputStream\s*\(",
        description="readObject on attacker data can trigger gadget chains leading to RCE.",
        why="Java native serialization reconstructs arbitrary classes present on the classpath.",
        preconditions="The stream originates from an untrusted source.",
        test_procedure="Authorized lab only; use a controlled gadget detection harness.",
        exploit_template="// Use ysoserial ONLY against your own authorized lab target",
        remediation={"java": "// Prefer a data format (JSON) with a strict schema, or use a\n// look-ahead ObjectInputFilter allowlisting expected classes."},
        why_patch_works="An ObjectInputFilter allowlist blocks unexpected gadget classes before they are instantiated.",
        regression_test={"java": "// assert deserialization of an unexpected class is rejected"},
        references=["https://cwe.mitre.org/data/definitions/502.html"],
        limitations="Flags the API; exploitability depends on classpath gadgets.",
        base_confidence="needs_context",
    ),
    # ---------------- Dangerous eval ----------------
    Rule(
        id="py-eval-exec",
        name="eval()/exec() on dynamic input",
        cwe="CWE-95",
        languages=["python"],
        sink=r"\b(eval|exec)\s*\(",
        description="eval/exec run their string argument as Python code.",
        why="Any user influence over the string yields arbitrary code execution.",
        preconditions="The evaluated string is attacker-influenced.",
        test_procedure="Authorized lab: supply `__import__('os').getpid()` and confirm execution.",
        exploit_template="# expr=__import__('os').getpid()",
        remediation={"python": "import ast\nvalue = ast.literal_eval(expr)  # only literals, never code"},
        why_patch_works="ast.literal_eval parses only literal structures (numbers, lists, dicts) and cannot call functions.",
        regression_test={"python": "def test_eval():\n    with pytest.raises(ValueError):\n        safe_parse(\"__import__('os')\")"},
        references=["https://cwe.mitre.org/data/definitions/95.html"],
        limitations="eval on a trusted constant is lower risk; confirm the source.",
    ),
    Rule(
        id="js-eval",
        name="eval()/Function() on dynamic input",
        cwe="CWE-95",
        languages=["javascript"],
        sink=r"\b(eval|new\s+Function)\s*\(",
        description="eval and the Function constructor execute strings as JavaScript.",
        why="User-controlled strings become executable code.",
        preconditions="The string is attacker-influenced.",
        test_procedure="Authorized lab: confirm injected code runs.",
        exploit_template="// JSON.parse is the usual intended operation",
        remediation={"javascript": "const value = JSON.parse(text);  // for data, not code"},
        why_patch_works="JSON.parse only accepts data; it never executes code.",
        regression_test={"javascript": "// assert injected expression does not run"},
        references=["https://cwe.mitre.org/data/definitions/95.html"],
        limitations="Flags the API regardless of argument source.",
    ),
    # ---------------- Hardcoded secrets ----------------
    Rule(
        id="generic-hardcoded-secret",
        name="Hardcoded secret / credential",
        cwe="CWE-798",
        languages=["python", "php", "javascript", "java", "c", "cpp", "shell"],
        sink=r"(password|passwd|secret|api[_-]?key|token|aws_secret|private_key)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
        description="A credential or key appears as a literal in source.",
        why="Anyone with source access obtains the secret; it also leaks into version control history.",
        preconditions="The literal is a real secret, not a placeholder.",
        test_procedure="Confirm whether the value authenticates against a real service; rotate if so.",
        exploit_template="# n/a — remove the secret and rotate it",
        remediation={"python": "import os\nAPI_KEY = os.environ['API_KEY']  # load from env / secret store"},
        why_patch_works="Loading from the environment keeps secrets out of source and VCS history.",
        regression_test={"python": "# CI secret-scan (e.g. gitleaks) blocks literal secrets"},
        references=["https://cwe.mitre.org/data/definitions/798.html"],
        limitations="High false-positive rate on placeholders/examples; always verify the value.",
        base_confidence="needs_context",
        flags=0,
    ),
    # ---------------- Insecure file upload ----------------
    Rule(
        id="py-upload-save-filename",
        name="Uploaded file saved using its client-supplied name",
        cwe="CWE-434",
        languages=["python"],
        sink=r"\.save\s*\(\s*[^)]*(filename|\.name)\b",
        description="An upload is written to disk using the attacker-controlled filename.",
        why="Allows path traversal in the name and writing executable extensions into served directories.",
        preconditions="Filename unsanitized and/or destination is web-served.",
        test_procedure="Authorized lab: upload `../../x.php` style names and dangerous extensions; confirm rejection.",
        exploit_template="# filename=../../var/www/shell.php",
        remediation={"python": "from werkzeug.utils import secure_filename\nname = secure_filename(f.filename)\nif ext(name) not in ALLOWED_EXT:\n    abort(400)\nf.save(os.path.join(UPLOAD_DIR, name))"},
        why_patch_works="secure_filename strips path components; an extension allowlist blocks executable types.",
        regression_test={"python": "def test_upload_traversal(client):\n    # '../../x.php' must not escape UPLOAD_DIR"},
        references=["https://cwe.mitre.org/data/definitions/434.html"],
        limitations="Cannot confirm whether sanitization exists elsewhere.",
    ),
    # ---------------- C memory safety ----------------
    Rule(
        id="c-unsafe-copy",
        name="Unbounded buffer copy (strcpy/gets/sprintf)",
        cwe="CWE-120",
        languages=["c", "cpp"],
        sink=r"\b(strcpy|strcat|gets|sprintf)\s*\(",
        description="A classic unbounded string function that can overflow a fixed buffer.",
        why="Input longer than the destination buffer corrupts adjacent memory, enabling crashes or code execution.",
        preconditions="Source length is not bounded by the destination size.",
        test_procedure="Authorized lab: supply input longer than the buffer under ASan and observe the overflow.",
        exploit_template="/* input of length > sizeof(buf) */",
        remediation={"c": "snprintf(buf, sizeof(buf), \"%s\", src);  /* or strlcpy */"},
        why_patch_works="snprintf/strlcpy take the destination size and truncate instead of overflowing.",
        regression_test={"c": "/* build with -fsanitize=address; long input must not overflow */"},
        references=["https://cwe.mitre.org/data/definitions/120.html"],
        limitations="gets is always unsafe; strcpy/sprintf can be safe with proven-bounded sources.",
    ),
]


def rules_for_language(language: str) -> list[Rule]:
    lang = LANG_ALIASES.get(language.lower(), language.lower())
    return [r for r in RULES if lang in r.languages]


def all_rule_summaries() -> list[dict]:
    return [
        {
            "id": r.id, "name": r.name, "cwe": r.cwe,
            "languages": r.languages, "references": r.references,
        }
        for r in RULES
    ]
