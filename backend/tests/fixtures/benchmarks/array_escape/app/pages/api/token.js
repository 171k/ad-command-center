// Array Escape (repro) — token minting + verification.
// Weaknesses embodied here:
//   * Hardcoded HMAC signing secret (CWE-321/798)
//   * Role claim trusted from the request body (CWE-285/915)
//   * Signature compared with ==, non-constant-time (CWE-347/208)
import crypto from "crypto";

// EXPECT: line 10 secret-exposed CWE-321 hardcoded signing key
const SIGNING_SECRET = "s3cr3t_hmac_key_do_not_ship_this";

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const mac = crypto
    .createHmac("sha256", SIGNING_SECRET)
    .update(body)
    .digest("hex");
  return `${body}.${mac}`;
}

export function verify(token) {
  const [body, mac] = String(token).split(".");
  const expected = crypto
    .createHmac("sha256", SIGNING_SECRET)
    .update(body)
    .digest("hex");
  // EXPECT: line 26 weak-signature-check CWE-347 non-constant-time compare
  if (mac != expected) return null;
  return JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
}

export default function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).end();
    return;
  }
  const { username, role } = req.body || {};
  // EXPECT: line 37 trust-role-claim CWE-285 role taken from client input
  const token = sign({ username, role: role || "user" });
  res.status(200).json({ token });
}
