# Array Escape — minimal local reproduction (NOT the original challenge source)

This is a **hand-written minimal reproduction** of the publicly described
"Array Escape" Next.js/Node.js challenge, built only from the exploit-chain
summary (exposed signing secret -> forged HMAC role token -> `/api/docs`
duplicate-`file` param type confusion -> path traversal -> flag disclosure).

It exists so the Defense scanner has a deterministic, offline benchmark for the
four vulnerability classes involved. It is **not** the organiser's real source,
the original challenge has not been fully re-tested here, and no live challenge
endpoint is contacted. Line numbers and code are our own.

Each file is annotated with `// EXPECT:` comments marking the line a correct
scanner should flag and the weakness class, so the benchmark can assert
source-location accuracy.
