#!/usr/bin/env python3
"""adtools, retrieve approved tools from the A&D Command Center without GitHub.

Two modes:
  online   : talks to the server over HTTPS (cert-verified) with your login.
  --offline: uses a local bundle (manifest.json + artifacts/), no network at all.

Integrity: every artifact is checked against the SHA-256 in the manifest / the
server's X-Checksum-SHA256 header before it is written or used. No `curl | bash`,
no execution of unverified downloads.

Commands:
  adtools list
  adtools search <query>
  adtools info <slug>
  adtools verify <slug>
  adtools install <slug> [--dest DIR]
  adtools login                      (online only; stores a session cookie)
  adtools offline-export [-o FILE]   (online only; downloads the full bundle)

Examples:
  export ADTOOLS_URL=https://itikad.site
  python3 adtools.py login
  python3 adtools.py search pwn
  python3 adtools.py install ffuf
  # fully offline, from an unzipped bundle directory:
  python3 adtools.py --offline --bundle . install ffuf
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import shutil
import ssl
import sys
import urllib.request
from pathlib import Path

HOME = Path(os.environ.get("ADTOOLS_HOME", str(Path.home() / ".adtools")))
COOKIE_FILE = HOME / "cookies"


def _die(msg: str, code: int = 1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


# ---------------- online client ----------------

class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.ctx = ssl.create_default_context()  # verifies certs
        self.cookie = COOKIE_FILE.read_text().strip() if COOKIE_FILE.exists() else ""

    def _req(self, path, data=None, headers=None, raw=False):
        url = f"{self.base}{path}"
        h = {"Accept": "application/json"}
        if self.cookie:
            h["Cookie"] = self.cookie
        if headers:
            h.update(headers)
        body = json.dumps(data).encode() if data is not None else None
        if body is not None:
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=body, headers=h, method="POST" if data is not None else "GET")
        resp = urllib.request.urlopen(req, context=self.ctx, timeout=60)
        if raw:
            return resp
        return json.loads(resp.read().decode())

    def login(self, username, password):
        url = f"{self.base}/api/auth/login"
        body = json.dumps({"username": username, "password": password}).encode()
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        resp = urllib.request.urlopen(req, context=self.ctx, timeout=30)
        cookies = resp.headers.get_all("Set-Cookie") or []
        jar = "; ".join(c.split(";", 1)[0] for c in cookies)
        if not jar:
            _die("login failed (no cookie returned)")
        HOME.mkdir(parents=True, exist_ok=True)
        COOKIE_FILE.write_text(jar)
        try:
            os.chmod(COOKIE_FILE, 0o600)
        except OSError:
            pass
        self.cookie = jar
        print(f"logged in as {username}; session saved to {COOKIE_FILE}")

    def manifest(self):
        return self._req("/api/tools/manifest")

    def download(self, slug, aid, dest: Path, expected_sha: str):
        resp = self._req(f"/api/tools/{slug}/artifacts/{aid}/download", raw=True)
        hdr_sha = resp.headers.get("X-Checksum-SHA256", "")
        tmp = dest.with_suffix(dest.suffix + ".part")
        h = hashlib.sha256()
        with open(tmp, "wb") as f:
            for chunk in iter(lambda: resp.read(1 << 20), b""):
                f.write(chunk); h.update(chunk)
        actual = h.hexdigest()
        if expected_sha and actual != expected_sha:
            tmp.unlink(missing_ok=True); _die(f"checksum mismatch (manifest) for {dest.name}")
        if hdr_sha and actual != hdr_sha:
            tmp.unlink(missing_ok=True); _die(f"checksum mismatch (server header) for {dest.name}")
        tmp.replace(dest)
        return actual


# ---------------- offline source ----------------

class OfflineBundle:
    def __init__(self, bundle_dir: Path):
        self.dir = bundle_dir
        mf = bundle_dir / "manifest.json"
        if not mf.exists():
            _die(f"no manifest.json in {bundle_dir}")
        self.man = json.loads(mf.read_text())

    def manifest(self):
        return self.man

    def artifact_path(self, storage_path: str) -> Path:
        return self.dir / "artifacts" / storage_path


# ---------------- shared helpers ----------------

def _find_tool(man, slug):
    for t in man["tools"]:
        if t["slug"] == slug:
            return t
    _die(f"unknown tool: {slug}")


def _pick_artifact(tool):
    arts = tool.get("artifacts") or []
    if not arts:
        return None
    # prefer this OS; else any
    plat = "windows" if os.name == "nt" else "ubuntu"
    for a in arts:
        if (a.get("os") or "any") in (plat, "any"):
            return a
    return arts[0]


# ---------------- commands ----------------

def cmd_list(src, _):
    man = src.manifest()
    for t in man["tools"]:
        print(f"{t['slug']:<16} {t['category']:<24} {t.get('version','') or '':<14} {t['name']}")


def cmd_search(src, args):
    q = args.query.lower()
    for t in src.manifest()["tools"]:
        blob = f"{t['slug']} {t['name']} {t.get('description','')} {' '.join(t.get('tags',[]))}".lower()
        if q in blob:
            print(f"{t['slug']:<16} {t['name']}, {t.get('description','')[:60]}")


def cmd_info(src, args):
    t = _find_tool(src.manifest(), args.slug)
    print(json.dumps({k: t.get(k) for k in
                      ("slug", "name", "category", "version", "license", "provenance",
                       "os_support", "dependencies", "install", "artifacts")}, indent=2))


def cmd_verify(src, args):
    t = _find_tool(src.manifest(), args.slug)
    arts = t.get("artifacts") or []
    if not arts:
        print(f"{args.slug}: no hosted artifacts (metadata only)"); return
    ok = True
    for a in arts:
        if isinstance(src, OfflineBundle):
            p = src.artifact_path(a["storage_path"])
            if not p.exists():
                print(f"  {a['filename']}: MISSING"); ok = False; continue
            actual = _sha256(p)
            good = actual == a["sha256"]
            print(f"  {a['filename']}: {'OK' if good else 'MISMATCH'} {a['sha256'][:16]}…")
            ok = ok and good
        else:
            r = src._req(f"/api/tools/{args.slug}/artifacts/{a['id']}/verify")
            print(f"  {a['filename']}: {'OK' if r.get('ok') else 'MISMATCH'}")
            ok = ok and bool(r.get("ok"))
    sys.exit(0 if ok else 2)


def cmd_install(src, args):
    t = _find_tool(src.manifest(), args.slug)
    a = _pick_artifact(t)
    dest_dir = Path(args.dest).expanduser()
    dest_dir.mkdir(parents=True, exist_ok=True)
    if a:
        dest = dest_dir / a["filename"]
        if isinstance(src, OfflineBundle):
            srcp = src.artifact_path(a["storage_path"])
            if not srcp.exists():
                _die(f"artifact missing in bundle: {a['filename']}")
            if _sha256(srcp) != a["sha256"]:
                _die(f"checksum mismatch for {a['filename']}")
            shutil.copy2(srcp, dest)
        else:
            src.download(args.slug, a["id"], dest, a["sha256"])
        # make executable if it looks like a program (no risky auto-run)
        try:
            if os.name != "nt" and not a["filename"].lower().endswith((".html", ".txt", ".json", ".zip", ".tar.gz")):
                os.chmod(dest, 0o755)
        except OSError:
            pass
        print(f"installed artifact: {dest}  (sha256 verified)")
    else:
        print(f"{args.slug}: no hosted artifact; follow the install instructions below.")
    plat = "windows" if os.name == "nt" else "ubuntu"
    instr = (t.get("install") or {}).get(plat) or (t.get("install") or {}).get("ubuntu")
    if instr:
        print("next step (review before running):")
        print(f"  {instr}")


def cmd_login(src, args):
    if not isinstance(src, Client):
        _die("login requires online mode")
    user = args.username or input("username: ")
    pw = os.environ.get("ADTOOLS_PASSWORD") or getpass.getpass("password: ")
    src.login(user, pw)


def cmd_offline_export(src, args):
    if not isinstance(src, Client):
        _die("offline-export requires online mode")
    resp = src._req("/api/tools/export/bundle", raw=True)
    out = Path(args.output)
    with open(out, "wb") as f:
        shutil.copyfileobj(resp, f)
    print(f"bundle saved: {out} ({out.stat().st_size} bytes)")


def main(argv=None):
    p = argparse.ArgumentParser(prog="adtools")
    p.add_argument("--url", default=os.environ.get("ADTOOLS_URL", "https://itikad.site"))
    p.add_argument("--offline", action="store_true")
    p.add_argument("--bundle", default=".")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list").set_defaults(fn=cmd_list)
    sp = sub.add_parser("search"); sp.add_argument("query"); sp.set_defaults(fn=cmd_search)
    sp = sub.add_parser("info"); sp.add_argument("slug"); sp.set_defaults(fn=cmd_info)
    sp = sub.add_parser("verify"); sp.add_argument("slug"); sp.set_defaults(fn=cmd_verify)
    sp = sub.add_parser("install"); sp.add_argument("slug"); sp.add_argument("--dest", default="."); sp.set_defaults(fn=cmd_install)
    sp = sub.add_parser("login"); sp.add_argument("--username"); sp.set_defaults(fn=cmd_login)
    sp = sub.add_parser("offline-export"); sp.add_argument("-o", "--output", default="adcc-tool-bundle.zip"); sp.set_defaults(fn=cmd_offline_export)
    args = p.parse_args(argv)
    src = OfflineBundle(Path(args.bundle)) if args.offline else Client(args.url)
    args.fn(src, args)


if __name__ == "__main__":
    main()
