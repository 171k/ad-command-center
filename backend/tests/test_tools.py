"""Tool Repository: catalog, checksum integrity, authenticated download, and the
full offline bundle flow (acceptance criteria 1-3)."""
import io
import zipfile


from app.tools import repository as repo


def _seed(client, h):
    client.post("/api/tools/seed", headers=h)


def test_catalog_seeded_and_searchable(auth):
    client, h = auth
    _seed(client, h)
    data = client.get("/api/tools").json()
    assert data["total"] >= 10
    assert "Binary Exploitation" in data["categories"]
    # search
    r = client.get("/api/tools", params={"q": "pwn"}).json()
    assert any(t["slug"] == "pwntools" for t in r["items"])


def test_upload_download_checksum(auth):
    client, h = auth
    _seed(client, h)
    # create a dedicated tool
    client.post("/api/tools", json={"slug": "demotool", "name": "Demo", "category": "General CTF Utilities"}, headers=h)
    payload = b"#!/bin/sh\necho hello from demotool\n"
    r = client.post("/api/tools/demotool/artifacts",
                    files={"file": ("demotool.sh", payload, "application/octet-stream")},
                    data={"os": "ubuntu", "arch": "any"}, headers=h)
    assert r.status_code == 201
    aid = r.json()["id"]
    expected = r.json()["sha256"]
    assert expected == repo.sha256_bytes(payload)

    # download — content matches, server returns checksum header, no GitHub involved
    dl = client.get(f"/api/tools/demotool/artifacts/{aid}/download")
    assert dl.status_code == 200
    assert dl.content == payload
    assert dl.headers["X-Checksum-SHA256"] == expected

    # server-side verify
    assert client.get(f"/api/tools/demotool/artifacts/{aid}/verify").json()["ok"] is True


def test_corrupt_artifact_detected(auth):
    client, h = auth
    _seed(client, h)
    client.post("/api/tools", json={"slug": "corrupt", "name": "C", "category": "General CTF Utilities"}, headers=h)
    r = client.post("/api/tools/corrupt/artifacts",
                    files={"file": ("x.bin", b"good-bytes", "application/octet-stream")}, headers=h)
    aid = r.json()["id"]
    sp = __import__("app").db.query_one("SELECT storage_path FROM tool_artifacts WHERE id=?", (aid,))["storage_path"]
    repo.artifact_abspath(sp).write_bytes(b"TAMPERED")  # corrupt on disk
    assert client.get(f"/api/tools/corrupt/artifacts/{aid}/verify").json()["ok"] is False


def test_offline_bundle_install(auth, tmp_path):
    client, h = auth
    _seed(client, h)
    client.post("/api/tools", json={"slug": "ffuf", "name": "ffuf", "category": "Web Security"}, headers=h)
    binary = b"\x7fELF-fake-ffuf-binary-bytes" * 10
    client.post("/api/tools/ffuf/artifacts",
                files={"file": ("ffuf", binary, "application/octet-stream")},
                data={"os": "ubuntu"}, headers=h)

    # export the offline bundle and unpack it
    bundle = client.get("/api/tools/export/bundle")
    assert bundle.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(bundle.content))
    names = zf.namelist()
    assert "manifest.json" in names and "adtools.py" in names
    assert any(n.startswith("artifacts/") and n.endswith("ffuf") for n in names)
    zf.extractall(tmp_path)

    # OFFLINE install via the bundled CLI logic — verifies checksum, places the file
    import importlib.util
    spec = importlib.util.spec_from_file_location("adtools_cli", tmp_path / "adtools.py")
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    src = mod.OfflineBundle(tmp_path)
    dest = tmp_path / "install"
    mod.cmd_install(src, type("A", (), {"slug": "ffuf", "dest": str(dest)}))
    installed = dest / "ffuf"
    assert installed.exists() and installed.read_bytes() == binary  # checksum-verified copy
