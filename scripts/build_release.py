"""Build a verifiable Provenant release: wheel + sdist, SHA256SUMS, a CycloneDX SBOM and a provenance record.

    python scripts/build_release.py [--out dist] [--publish-site]

--publish-site also copies the artifacts to dashboard/download/ so the website's Download button serves the
exact files whose hashes are listed (the hosted site is static; nothing there is generated at request time).

What this proves: that the files you download are the ones built from the recorded commit (compare SHA256SUMS,
and on GitHub releases the Sigstore attestation made by .github/workflows/release.yml). It does not prove the
software is free of vulnerabilities. Provenant has no runtime dependencies, so the SBOM lists only itself and
its Python requirement; build tooling is recorded in the provenance file.
"""
from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def version() -> str:
    for line in (ROOT / "pyproject.toml").read_text().splitlines():
        if line.startswith("version"):
            return line.split('"')[1]
    raise SystemExit("no version in pyproject.toml")


def main(argv: list[str]) -> int:
    out = ROOT / (argv[argv.index("--out") + 1] if "--out" in argv else "dist")
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain", "--", "agentshield", "pyproject.toml"], cwd=ROOT,
                                capture_output=True, text=True).stdout.strip())
    subprocess.run([sys.executable, "-m", "build", "--sdist", "--wheel", "--outdir", str(out), str(ROOT)], check=True,
                   stdout=subprocess.DEVNULL)
    shutil.rmtree(ROOT / "build", ignore_errors=True)
    for egg in ROOT.glob("*.egg-info"):
        shutil.rmtree(egg, ignore_errors=True)
    v = version()
    arts = sorted(p for p in out.iterdir() if p.suffix in (".whl", ".gz"))
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                     "component": {"type": "application", "name": "provenant", "version": v,
                                   "purl": f"pkg:pypi/provenant@{v}",
                                   "externalReferences": [{"type": "vcs", "url": "https://github.com/MithunSidhaarth/provenant"}]}},
        "components": [{"type": "file", "name": a.name, "hashes": [{"alg": "SHA-256", "content": sha256(a)}]} for a in arts],
        "dependencies": [{"ref": f"pkg:pypi/provenant@{v}", "dependsOn": []}],
        "properties": [{"name": "runtime-dependencies", "value": "none (Python standard library only)"},
                       {"name": "requires-python", "value": ">=3.10"}],
    }
    (out / "sbom.cdx.json").write_text(json.dumps(sbom, indent=1))
    prov = {"artifact_version": v, "source": "https://github.com/MithunSidhaarth/provenant", "commit": commit,
            "working_tree_modified": dirty, "built_at_utc": sbom["metadata"]["timestamp"],
            "builder": {"python": platform.python_version(), "platform": platform.platform(),
                        "tool": "python -m build (setuptools backend)", "script": "scripts/build_release.py"},
            "artifacts": {a.name: sha256(a) for a in arts}}
    (out / "provenance.json").write_text(json.dumps(prov, indent=1))
    files = sorted(p for p in out.iterdir() if p.name != "SHA256SUMS")
    (out / "SHA256SUMS").write_text("".join(f"{sha256(p)}  {p.name}\n" for p in files))
    if "--publish-site" in argv:
        site = ROOT / "dashboard" / "download"
        shutil.rmtree(site, ignore_errors=True)
        site.mkdir(parents=True)
        for p in out.iterdir():
            shutil.copy2(p, site / p.name)
        (site / "latest.json").write_text(json.dumps({"version": v, "commit": commit, "wheel": next(a.name for a in arts if a.suffix == ".whl"),
                                                      "sdist": next(a.name for a in arts if a.suffix == ".gz"),
                                                      "sha256": prov["artifacts"]}, indent=1))
    print(json.dumps(prov, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
