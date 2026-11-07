#!/usr/bin/env python3
"""Generate common password mutations from a base word (offline, bounded).

Reads {"word": "...", "years": true|false} on stdin; writes {"mutations":[...]}.
Deterministic, capped output. No network, no files.
"""
import json
import sys

LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})
SUFFIXES = ["", "1", "123", "!", "123!", "@", "#", "2024", "2025", "2026"]


def mutate(word: str, years: bool) -> list[str]:
    word = word[:32]
    bases = {word, word.lower(), word.upper(), word.capitalize(), word.translate(LEET)}
    suf = SUFFIXES if years else [s for s in SUFFIXES if not s.isdigit() or len(s) < 4]
    out = []
    seen = set()
    for b in bases:
        for s in suf:
            cand = b + s
            if cand not in seen:
                seen.add(cand); out.append(cand)
            if len(out) >= 500:
                return out
    return out


def main():
    args = json.loads(sys.stdin.read() or "{}")
    word = str(args.get("word", "")).strip()
    if not word:
        print(json.dumps({"error": "word is required"})); return
    muts = mutate(word, bool(args.get("years", True)))
    print(json.dumps({"base": word[:32], "count": len(muts), "mutations": muts}))


if __name__ == "__main__":
    main()
