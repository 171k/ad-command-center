// Secure counterpart to Array Escape — must NOT raise equivalent findings.
import fs from "fs";
import path from "path";
import crypto from "crypto";

// Secret loaded from the environment, never embedded, never sent to the client.
const SIGNING_SECRET = process.env.SIGNING_SECRET;

const DOCS_DIR = path.resolve(process.cwd(), "docs");

function verify(token) {
  const [body, mac] = String(token).split(".");
  const expected = crypto.createHmac("sha256", SIGNING_SECRET).update(body).digest("hex");
  const a = Buffer.from(mac || "", "hex");
  const b = Buffer.from(expected, "hex");
  // Constant-time compare; reject on any length/signature mismatch.
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
}

export default function handler(req, res) {
  const claims = verify(req.headers["x-auth-token"]);
  if (!claims || claims.role !== "admin") {
    res.status(403).json({ error: "admin required" });
    return;
  }

  // Reject anything that is not a single string parameter (defeats ?file=a&file=b).
  const raw = req.query.file;
  if (typeof raw !== "string") {
    res.status(400).json({ error: "file must be a single string" });
    return;
  }

  // Canonicalise, then enforce the directory boundary on the RESOLVED path.
  const full = path.resolve(DOCS_DIR, raw);
  const rel = path.relative(DOCS_DIR, full);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    res.status(400).json({ error: "outside docs dir" });
    return;
  }

  const data = fs.readFileSync(full, "utf8");
  res.status(200).send(data);
}
