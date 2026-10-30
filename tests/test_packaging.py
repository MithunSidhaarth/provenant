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
        shutil.copytree(ROOT, src, ignore=shutil.ignore_patterns(".git", "node_modules", "dist", "build", "*.egg-info", "web", "dashboard"))
        r = subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps", "-q", "-w", str(t / "whl"), str(src)],
                           capture_output=True, text=True)
        if r.returncode:
            raise unittest.SkipTest(f"cannot build a wheel here: {r.stderr[-300:]}")
        cls.wheel = next((t / "whl").glob("provenant-*.whl"))
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
