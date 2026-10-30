"""Build the wheel, install it into a fresh virtual environment, and run it from outside the source tree,
through every entry point a Windows or Unix user might use."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import venv
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@unittest.skipUnless(os.environ.get("PROVENANT_SKIP_PACKAGING") != "1", "packaging test disabled")
class Packaging(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = Path(cls.tmp.name)
        src = t / "src"                                    # build from a copy so the checkout stays clean
        shutil.copytree(ROOT, src, ignore=shutil.ignore_patterns(".git", "node_modules", "dist", "build", "*.egg-info", "web", "media", "download"))
        r = subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps", "-q", "-w", str(t / "whl"), str(src)],
                           capture_output=True, text=True)
        if r.returncode:
            raise unittest.SkipTest(f"cannot build a wheel here: {r.stderr[-300:]}")
        cls.wheel = next((t / "whl").glob("provenant_agent_shield-*.whl"))
        venv.EnvBuilder(with_pip=True).create(t / "venv")
        bindir = t / "venv" / ("Scripts" if sys.platform == "win32" else "bin")
        cls.py = bindir / ("python.exe" if sys.platform == "win32" else "python")
        cls.exe = bindir / ("provenant.exe" if sys.platform == "win32" else "provenant")
        subprocess.run([str(cls.py), "-m", "pip", "install", "-q", "--no-index", str(cls.wheel)], check=True)
        cls.run_dir = t / "elsewhere"
        cls.run_dir.mkdir()
        cls.env = {"PATH": str(bindir), "HOME": str(t / "home"), "USERPROFILE": str(t / "home"), "APPDATA": str(t / "home"),
                   "PROVENANT_HOME": str(t / "home" / ".provenant"), "NO_COLOR": "1", "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_in_venv(self, *argv):
        r = subprocess.run([str(a) for a in argv], capture_output=True, text=True, cwd=self.run_dir, env=self.env, timeout=120)
        return r.returncode, r.stdout + r.stderr

    def test_wheel_bundles_resources_and_entry_point(self):
        z = zipfile.ZipFile(self.wheel)
        names = z.namelist()
        for need in ("agentshield/guard_policy.json", "agentshield/cli.py", "agentshield/classifier.py",
                     "agentshield/onboarding.py", "agentshield/__main__.py", "provenant/__main__.py"):
            self.assertIn(need, names)
        ep = next(n for n in names if n.endswith("entry_points.txt"))
        self.assertIn("provenant = agentshield.cli:main", z.read(ep).decode())
        self.assertNotIn("tests/", " ".join(names))

    def test_every_entry_point_runs_outside_the_repo(self):
        version = zipfile.ZipFile(self.wheel).filename.split("-")[1]
        for argv in ([self.exe, "--version"], [self.py, "-m", "provenant", "--version"],
                     [self.py, "-m", "agentshield", "--version"], [self.py, "-m", "agentshield.cli", "--version"]):
            code, out = self.run_in_venv(*argv)
            self.assertEqual(code, 0, (argv, out))
            self.assertIn(version, out)

    def test_wheel_ships_the_dashboard_and_demo_data(self):
        names = zipfile.ZipFile(self.wheel).namelist()
        for need in ("provenant_dashboard/index.html", "provenant_dashboard/ops.js", "provenant_dashboard/ops.css",
                     "provenant_dashboard/site.html", "provenant_dashboard/app.js", "provenant_policy/policy.json",
                     "provenant_evals/policy_scenarios.json"):
            self.assertIn(need, names)
        self.assertTrue(any(n.startswith("provenant_scenarios/") and n.endswith(".json") for n in names))
        self.assertFalse(any("/media/" in n or "/download/" in n for n in names), "release files and video stay out of the wheel")

    def test_installed_dashboard_serves_from_the_wheel(self):
        # Regression: `provenant dashboard` from a pip install crashed with FileNotFoundError on index.html.
        code = ("import threading, urllib.request; from agentshield import server; "
                "s = server.serve('127.0.0.1', 0); threading.Thread(target=s.serve_forever, daemon=True).start(); "
                "base = 'http://127.0.0.1:%d' % s.server_address[1]; "
                "print(*[urllib.request.urlopen(base + p, timeout=10).status for p in ('/', '/ops.js', '/site.html', '/api/scenarios', '/api/guard/status')]); "
                "print(server.DASHBOARD)")
        rc, out = self.run_in_venv(self.py, "-c", code)
        self.assertEqual(rc, 0, out)
        self.assertIn("200 200 200 200 200", out)
        self.assertIn("provenant_dashboard", out)
        self.assertFalse(any((Path(self.tmp.name) / "venv").rglob("audit-*.jsonl")), "demo audits must not be written into the venv")

    def test_installed_wheel_verifies_enforcement(self):
        code, out = self.run_in_venv(self.py, "-m", "provenant", "verify", "--json")
        self.assertEqual(code, 0, out)
        self.assertTrue(json.loads(out)["passed"])
        code, out = self.run_in_venv(self.exe, "doctor", "--json")
        checks = {c["id"]: c for c in json.loads(out)["checks"]}
        self.assertEqual(checks["resources"]["status"], "ok")
        self.assertEqual(checks["command"]["status"], "ok")        # the venv's bin is on PATH here


if __name__ == "__main__":
    unittest.main()
