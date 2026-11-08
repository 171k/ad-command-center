#!/usr/bin/env python3
"""Shannon entropy + byte-class breakdown of input (spot encoding/encryption).

Reads {"text": "..."} on stdin; writes stats on stdout. Offline, deterministic.
"""
import json
import math
import sys
from collections import Counter


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 4)


def main():
    args = json.loads(sys.stdin.read() or "{}")
    text = str(args.get("text", ""))[:100_000]
    data = text.encode("utf-8", "replace")
    ent = shannon(data)
    printable = sum(1 for b in data if 32 <= b < 127)
    verdict = ("high, likely encrypted/compressed/random" if ent > 7.2
               else "medium, possibly encoded" if ent > 4.5
               else "low, likely plain text")
    print(json.dumps({
        "length": len(data),
        "shannon_entropy_bits_per_byte": ent,
        "printable_ratio": round(printable / len(data), 3) if data else 0,
        "verdict": verdict,
    }))


if __name__ == "__main__":
    main()
