"""The website's Get Started guide is generated from web/src/onboarding.json. Every command it shows must exist
in this CLI and run without a usage error, its version and URLs must match this release, and its expected
verify output must match what `provenant verify` really prints."""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
G = json.loads((ROOT / "web/src/onboarding.json").read_text(encoding="utf-8"))
VERSION = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)
FULL = re.compile(r"^(py|python3|curl|\(Invoke|winget|brew|sudo|pipx|irm|powershell)\b")   # same rule as GetStarted.jsx


def provenant_commands() -> set[str]:
    cmds = {G["verify"][k] for k in ("command", "status", "doctor")} | {G["model"]["check"], G["model"]["test"]}
    for c in G["clients"]:
        cmds |= {c[k] for k in ("setup", "setup_apply", "undo") if k in c}
    for t in G["troubleshooting"]:
        for v in t["verify"].values():
            if not FULL.match(v):
                cmds.add(v)
            elif " -m provenant " in v:
                cmds.add(v.split(" -m provenant ", 1)[1])
    return cmds


class SiteCommands(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        h = self.tmp.name
        self.env = dict(os.environ, HOME=h, USERPROFILE=h, APPDATA=h, PROVENANT_HOME=str(Path(h) / ".provenant"), NO_COLOR="1")

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, line):
        r = subprocess.run([sys.executable, str(ROOT / "provenant.py"), *line.split()], env=self.env, input="",
                           capture_output=True, text=True, timeout=60, cwd=self.tmp.name)
        return r.returncode, r.stdout + r.stderr

    def test_every_command_exists(self):
        cmds = provenant_commands()
        self.assertGreater(len(cmds), 10)
        for line in sorted(cmds):
            code, out = self.run_cli(line)
            self.assertNotIn("unknown command", out, line)
            self.assertNotIn("usage:", out.lower(), line)
            self.assertNotIn("Traceback", out, line)

    def test_version_and_urls_match_this_release(self):
        self.assertEqual(G["version"], VERSION)
        wheel = f"provenant_agent_shield-{VERSION}-py3-none-any.whl"
        self.assertTrue(G["wheel_url"].endswith("/dist/" + wheel))
        self.assertTrue((ROOT / "dist" / wheel).exists(), "build the release: scripts/build_release.py --publish-site")
        for m in G["methods"]:
            for shell, cmd in m["commands"].items():
                if m["id"] != "installer":
                    self.assertIn(G["wheel_url"], cmd)
                for script in re.findall(r"/main/(install\.(?:ps1|sh))", cmd):
                    self.assertTrue((ROOT / script).exists(), script)
        for script in ("install.sh", "install.ps1"):
            self.assertIn(VERSION, (ROOT / script).read_text(), f"{script} must install {VERSION}")
        latest = json.loads((ROOT / "dashboard/download/latest.json").read_text())
        self.assertEqual(latest["version"], VERSION)
        self.assertEqual(latest["urls"]["wheel"], G["wheel_url"])

    def test_expected_verify_output_is_real(self):
        code, out = self.run_cli("verify")
        self.assertEqual(code, 0, out)
        for line in G["verify"]["expected"]:
            action = line.split(": expected")[0].split(": 4 entries")[0]
            self.assertIn(action.split(":")[0], out, line)
        self.assertIn("Enforcement verified", out)

    def test_status_levels_match_cli(self):
        code, out = self.run_cli("status --json")
        p = json.loads(out)["protection"]
        self.assertEqual([l["id"] for l in G["levels"]], list(p["layers"]))

    def test_model_status_is_truthful(self):
        self.assertEqual(G["model"]["status"], "not_available")
        self.assertFalse((ROOT / "model" / "MODEL_CARD.md").exists(), "a filled model card means the site status must change")
        page = (ROOT / "web/src/GetStarted.jsx").read_text()
        self.assertNotRegex(page, r"(?i)we (ran|executed)|detected your|protected!")


if __name__ == "__main__":
    unittest.main()
