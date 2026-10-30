"""Verify a published Provenant wheel is real: HTTP status, content type, size, SHA-256, zip integrity, metadata,
and (with --install) that it installs into a fresh virtual environment and runs outside the source tree.

    python scripts/check_download.py [URL] [--sha256 HEX] [--install]

With no URL it checks the wheel URL in dashboard/download/latest.json. Exit code 0 only if every check passes.
This is what catches the 0.8.0 failure mode: a "download" that is really an HTML login page.
"""
from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tempfile
import urllib.request
import venv
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def check(url: str, sha: str | None, install: bool) -> dict:
    out: dict = {"url": url, "checks": {}}
    req = urllib.request.Request(url, headers={"User-Agent": "provenant-check-download"})
    with urllib.request.urlopen(req, timeout=60) as r:
        body, status, ctype, final = r.read(), r.status, r.headers.get("Content-Type", ""), r.geturl()
    c = out["checks"]
    out.update(final_url=final, bytes=len(body), content_type=ctype)
    c["http_200"] = status == 200
    c["not_html"] = "html" not in ctype.lower() and not body[:200].lstrip().lower().startswith((b"<!doctype", b"<html"))
    c["zip_magic"] = body[:4] == b"PK\x03\x04"
    digest = hashlib.sha256(body).hexdigest()
    out["sha256"] = digest
    if sha:
        c["sha256_match"] = digest == sha
    try:
        z = zipfile.ZipFile(io.BytesIO(body))
        c["zip_integrity"] = z.testzip() is None
        names = z.namelist()
        meta = next(n for n in names if n.endswith(".dist-info/METADATA"))
        out["metadata_version"] = next(l.split(":", 1)[1].strip() for l in z.read(meta).decode().splitlines() if l.startswith("Version:"))
        c["bundles_policy"] = "agentshield/guard_policy.json" in names
        c["has_entry_point"] = any(n.endswith("entry_points.txt") and b"agentshield.cli:main" in z.read(n) for n in names)
    except Exception as exc:                               # noqa: BLE001 - any failure is a failed check
        c["zip_integrity"] = False
        out["error"] = f"{type(exc).__name__}: {exc}"
    if install and all(c.values()):
        with tempfile.TemporaryDirectory() as tmp:
            whl = Path(tmp) / url.rsplit("/", 1)[-1]
            whl.write_bytes(body)
            env_dir = Path(tmp) / "venv"
            venv.EnvBuilder(with_pip=True).create(env_dir)
            py = env_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
            exe = env_dir / ("Scripts/provenant.exe" if sys.platform == "win32" else "bin/provenant")
            r1 = subprocess.run([str(py), "-m", "pip", "install", "-q", "--no-index", str(whl)], capture_output=True, text=True)
            c["pip_install"] = r1.returncode == 0
            env = {"PROVENANT_HOME": str(Path(tmp) / "home"), "HOME": str(Path(tmp) / "h"), "NO_COLOR": "1",
                   "PATH": "", "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", "")}
            r2 = subprocess.run([str(exe), "--version"], capture_output=True, text=True, cwd=tmp, env=env)
            c["entry_point_runs"] = r2.returncode == 0 and out.get("metadata_version", "?") in r2.stdout
            r3 = subprocess.run([str(py), "-m", "provenant", "verify", "--json"], capture_output=True, text=True, cwd=tmp, env=env)
            c["verify_passes_outside_repo"] = r3.returncode == 0 and json.loads(r3.stdout or "{}").get("passed") is True
    out["ok"] = all(c.values())
    return out


def main(argv: list[str]) -> int:
    latest = json.loads((ROOT / "dashboard" / "download" / "latest.json").read_text())
    pos = [a for a in argv if not a.startswith("--") and a != (argv[argv.index("--sha256") + 1] if "--sha256" in argv else None)]
    url = pos[0] if pos else latest["urls"]["wheel"]
    sha = argv[argv.index("--sha256") + 1] if "--sha256" in argv else latest["sha256"].get(url.rsplit("/", 1)[-1])
    r = check(url, sha, "--install" in argv)
    print(json.dumps(r, indent=1))
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
