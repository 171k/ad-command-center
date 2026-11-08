// Array Escape (repro) — /api/docs serves documentation files.
// Weaknesses embodied here:
//   * Duplicate-query-parameter type confusion (CWE-1286/CWE-20)
//   * Path traversal via unsafe join + bypassable prefix check (CWE-22)
//   * Protected flag disclosure once containment is escaped
import fs from "fs";
import path from "path";
import { verify } from "./token";

const DOCS_DIR = path.join(process.cwd(), "docs");

// Only admins may read the docs; the role comes from a forgeable token.
function requireAdmin(req) {
  const claims = verify(req.headers["x-auth-token"]);
  if (!claims || claims.role !== "admin") {
    return false;
  }
  return true;
}

function resolveDoc(name) {
  // EXPECT: line 23 unsafe-join CWE-22 user value joined without canonicalisation
  const full = path.join(DOCS_DIR, name);
  // Prefix check on the *unresolved* path — bypassable with ../ and symlinks.
  if (!full.startsWith(DOCS_DIR)) {
    throw new Error("outside docs dir");
  }
  return full;
}

export default function handler(req, res) {
  if (!requireAdmin(req)) {
    res.status(403).json({ error: "admin required" });
    return;
  }

  // Express/Next parse repeated query keys (?file=a&file=b) into an ARRAY.
  // Code written for the string case silently receives an array here.
  // EXPECT: line 44 dup-param-type-confusion CWE-1286 file may be string or array
  const file = req.query.file;

  // When `file` is an array, String(file) == "a,b" and the join/traversal
  // check behaves differently than the author assumed for the string case.
  const name = Array.isArray(file) ? file[file.length - 1] : file;

  let target;
  try {
    target = resolveDoc(name);
  } catch (e) {
    res.status(400).json({ error: String(e.message) });
    return;
  }

  // EXPECT: line 57 path-read CWE-22 filesystem read of user-controlled path
  const data = fs.readFileSync(target, "utf8");
  res.status(200).send(data);
}
