#!/usr/bin/env python3
"""Dictionary-check an unsalted hash against a small BUNDLED wordlist.

Reads {"hash": "...", "algo": "md5|sha1|sha256"} on stdin.
Offline, bounded (fixed small list), CPU-limited by the runner. This is a
convenience check for weak hashes — not a cracking rig. No network, no files.
"""
import hashlib
import json
import sys

# Small bundled list of common CTF/weak passwords (kept intentionally short).
WORDS = [
    "password", "123456", "123456789", "qwerty", "abc123", "password1",
    "admin", "root", "toor", "letmein", "welcome", "monkey", "dragon",
    "flag", "secret", "changeme", "iloveyou", "sunshine", "princess",
    "football", "charlie", "aa123456", "donald", "password123", "qwerty123",
    "1q2w3e4r", "zaq12wsx", "superman", "batman", "trustno1", "hello",
    "test", "test123", "guest", "user", "login", "pass", "ctf", "hackme",
    "administrator", "p@ssw0rd", "passw0rd", "qazwsx", "123123", "000000",
    "654321", "michael", "shadow", "master", "jennifer", "hunter",
]
ALGOS = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256}


def main():
    args = json.loads(sys.stdin.read() or "{}")
    target = str(args.get("hash", "")).strip().lower()[:128]
    algo = str(args.get("algo", "md5")).lower()
    if algo not in ALGOS:
        print(json.dumps({"error": f"algo must be one of {list(ALGOS)}"})); return
    fn = ALGOS[algo]
    tried = 0
    for w in WORDS:
        tried += 1
        if fn(w.encode()).hexdigest() == target:
            print(json.dumps({"cracked": True, "plaintext": w, "algo": algo, "tried": tried}))
            return
    print(json.dumps({"cracked": False, "algo": algo, "tried": tried,
                      "note": "Not in the bundled wordlist. Use a full tool offline on Kali for more."}))


if __name__ == "__main__":
    main()
