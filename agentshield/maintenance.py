"""Local dashboard launcher, diagnostics and package updater."""
from __future__ import annotations

import json
import subprocess
import sys

INSTALL_HINT = ("irm https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.ps1 | iex   (Windows)\n"
                "  curl -fsSL https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.sh | sh   (macOS/Linux)")


def dashboard(args: list[str]) -> int:
    from . import server
    options = list(args)
    if "--open" not in options:
        options.append("--open")
    return server.main(options) or 0


def update(args: list[str]) -> int:
    package = "provenant-agent-shield"
    if "--check" in args or "--dry-run" in args:
        try:
            result = subprocess.run([sys.executable, "-m", "pip", "index", "versions", package],
                                    capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"Update check failed: {exc}")
            return 1
        if result.returncode != 0 and "No matching distribution" in (result.stdout + result.stderr):
            print(f"{package} is not published on PyPI yet. Reinstall the latest wheel with the one-line installer:\n"
                  f"  {INSTALL_HINT}")
            return 1
        print((result.stdout + result.stderr).strip() or "No version information returned.")
        return 0 if result.returncode == 0 else 1
    print("Updating Provenant from the official PyPI distribution…")
    try:
        result = subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", package], check=False)
    except OSError as exc:
        print(f"Could not start pip: {exc}")
        return 1
    if result.returncode:
        print("Update failed. If the package is not on PyPI yet, reinstall with the one-line installer:\n"
              f"  {INSTALL_HINT}")
        return result.returncode
    print("Update installed. Restart Provenant and connected AI clients to load the new version.")
    return 0


def test(as_json: bool = False) -> int:
    """Exercise safe enforcement and verify local configuration and audit integrity."""
    from . import guard, onboarding
    enforcement = onboarding.self_test()
    doctor = onboarding.doctor()
    audit = guard.Store().audit.verify()
    checks = [
        {"id": "enforcement", "ok": bool(enforcement.get("passed")), "detail": "safe allow/block/approval checks"},
        {"id": "environment", "ok": bool(doctor.get("ok")), "detail": "installation and configuration checks"},
        {"id": "audit", "ok": bool(audit.get("ok")), "detail": f"{audit.get('checked', 0)} audit entries verified"},
    ]
    report = {"ok": all(item["ok"] for item in checks), "checks": checks,
              "note": "This does not prove that every external MCP server is healthy; test each server in its real client too."}
    if as_json:
        print(json.dumps(report, indent=2))
    else:
        for item in checks:
            print(f"[{'PASS' if item['ok'] else 'FAIL'}] {item['id']}: {item['detail']}")
        print(report["note"])
    return 0 if report["ok"] else 1
