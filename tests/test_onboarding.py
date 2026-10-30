"""0.9.0 onboarding: setup is safe, idempotent and reversible; status is layered; verify proves enforcement."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agentshield import cli

ROOT = Path(__file__).resolve().parent.parent
ORIGINAL = {"theme": "dark", "mcpServers": {
    "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/w"], "env": {"X": "1"}},
    "remote": {"type": "http", "url": "https://mcp.example/mcp"}}}


class Onboarding(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.cursor = self.home / ".cursor" / "mcp.json"
        self.cursor.parent.mkdir(parents=True)
        self.cursor.write_text(json.dumps(ORIGINAL))
        self.env = dict(os.environ, HOME=str(self.home), USERPROFILE=str(self.home),
                        APPDATA=str(self.home / "AppData" / "Roaming"), PROVENANT_HOME=str(self.home / ".provenant"),
                        NO_COLOR="1", PATH=os.environ.get("PATH", ""))

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        r = subprocess.run([sys.executable, str(ROOT / "provenant.py"), *args], env=self.env, input="",
                           capture_output=True, text=True, timeout=60, cwd=self.home)
        return r.returncode, r.stdout + r.stderr

    def backups(self):
        return [p for p in self.cursor.parent.iterdir() if ".provenant-backup-" in p.name]

    def test_setup_needs_consent_off_a_terminal(self):
        code, out = self.run_cli("setup")
        self.assertEqual(code, 1)
        self.assertIn("nothing was changed", out)
        self.assertEqual(json.loads(self.cursor.read_text()), ORIGINAL)
        self.assertEqual(self.backups(), [])

    def test_setup_is_idempotent_preserves_config_and_rolls_back(self):
        code, out = self.run_cli("setup", "--yes", "--client", "cursor")
        self.assertEqual(code, 0, out)
        cfg = json.loads(self.cursor.read_text())
        self.assertEqual(cfg["theme"], "dark")                                 # unrelated keys untouched
        self.assertEqual(cfg["mcpServers"]["fs"]["env"], {"X": "1"})
        self.assertEqual(cfg["mcpServers"]["remote"], ORIGINAL["mcpServers"]["remote"])
        self.assertIn("proxy", cfg["mcpServers"]["fs"]["args"])
        self.assertEqual(len(self.backups()), 1)
        first = self.cursor.read_text()
        code, out = self.run_cli("setup", "--yes", "--client", "cursor")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.cursor.read_text(), first)                       # no double wrapping
        self.assertEqual(self.cursor.read_text().count("_provenant_original"), 1)
        code, out = self.run_cli("rollback", "--yes", "--json")
        self.assertEqual(code, 0, out)
        self.assertEqual(json.loads(self.cursor.read_text()), ORIGINAL)       # exact original restored
        code, out = self.run_cli("rollback", "--yes")
        self.assertIn("Nothing to undo", out)

    def test_antigravity_config_is_wrapped_and_restored(self):
        ag = self.home / ".gemini" / "config" / "mcp_config.json"
        ag.parent.mkdir(parents=True)
        original = {"mcpServers": {"local": {"command": "npx", "args": ["-y", "x"], "env": {"K": "v"}},
                                   "remote": {"serverUrl": "https://mcp.example/mcp"}}}
        ag.write_text(json.dumps(original))
        code, out = self.run_cli("setup", "--yes", "--client", "antigravity")
        self.assertEqual(code, 0, out)
        cfg = json.loads(ag.read_text())
        self.assertIn("proxy", cfg["mcpServers"]["local"]["args"])
        self.assertEqual(cfg["mcpServers"]["remote"], original["mcpServers"]["remote"])   # remote left alone
        self.assertEqual(json.loads(self.cursor.read_text()), ORIGINAL)                    # other clients untouched
        code, out = self.run_cli("rollback", "--yes", "--client", "antigravity")
        self.assertEqual(json.loads(ag.read_text()), original)

    def test_missing_clients_reported_and_status_layers(self):
        code, out = self.run_cli("setup", "--dry-run")
        self.assertIn("Claude Desktop    not installed", out)
        self.assertIn("Windsurf          not installed", out)
        code, out = self.run_cli("status", "--json")
        p = json.loads(out)["protection"]
        self.assertEqual(p["level"], "engine")                                 # installed is not protected
        self.assertFalse(p["layers"]["configured"])
        self.assertEqual(p["next"], "run provenant setup")
        self.run_cli("setup", "--yes", "--client", "cursor")
        p = json.loads(self.run_cli("status", "--json")[1])["protection"]
        self.assertEqual(p["level"], "configured")                             # configured, but no traffic yet
        self.assertFalse(p["layers"]["connected"])

    def test_verify_proves_enforcement_and_reports_missing_integrations(self):
        code, out = self.run_cli("verify", "--json")
        self.assertEqual(code, 0, out)
        r = json.loads(out)
        self.assertTrue(r["passed"])
        ids = {s["id"]: s for s in r["steps"]}
        self.assertEqual(ids["unauthorized_denied"]["got"], "DENY")
        self.assertEqual(ids["side_effect_absent"]["got"], "present")
        self.assertEqual(ids["approval_required"]["got"], "REQUIRE_APPROVAL")
        self.assertEqual(ids["exact_args_bound"]["got"], "refused")
        self.assertEqual(len(r["audit_entries"]), 4)
        self.assertFalse(r["protection"]["layers"]["configured"])             # no client set up: says so
        self.assertTrue(r["not_verified"])
        code, out = self.run_cli("status", "--json")
        self.assertTrue(json.loads(out)["protection"]["layers"]["verified"])
        code, out = self.run_cli("pending")
        self.assertIn("Nothing is waiting", out)                               # the test queues nothing
        code, out = self.run_cli("verify", "--audit-only")
        self.assertIn("intact", out)

    def test_partial_failure_is_reported(self):
        windsurf = self.home / ".codeium" / "windsurf" / "mcp_config.json"
        windsurf.parent.mkdir(parents=True)
        windsurf.write_text(json.dumps(ORIGINAL))
        real_save = cli._save

        def flaky(path, data):
            if "windsurf" in str(path):
                raise OSError("read-only")
            real_save(path, data)
        with mock.patch.dict(os.environ, {"HOME": str(self.home), "USERPROFILE": str(self.home),
                                          "PROVENANT_HOME": str(self.home / ".provenant")}), \
                mock.patch.object(cli, "_save", flaky), mock.patch("pathlib.Path.home", return_value=self.home), \
                mock.patch("shutil.which", return_value=None):
            code = cli.cmd_setup(yes=True)
        self.assertEqual(code, 1)
        self.assertIn("_provenant_original", self.cursor.read_text())
        self.assertNotIn("_provenant_original", windsurf.read_text())

    def test_doctor_reports_without_secrets(self):
        (self.home / ".provenant").mkdir(exist_ok=True)
        (self.home / ".provenant" / "model.json").write_text(json.dumps(
            {"enabled": True, "endpoint": "https://m.example/v1/chat/completions", "api_key_env": "PV_TEST_KEY"}))
        self.env["PV_TEST_KEY"] = "sk-live-should-never-print-42"
        code, out = self.run_cli("doctor", "--json")
        r = json.loads(out)
        self.assertNotIn("sk-live-should-never-print-42", out)
        ids = {c["id"]: c for c in r["checks"]}
        for k in ("python", "package", "command", "resources", "state", "policy", "audit", "model"):
            self.assertIn(k, ids)
        self.assertEqual(ids["model"]["status"], "ok")
        cfg = json.loads(self.cursor.read_text())
        cfg["mcpServers"]["fs"] = {"command": str(self.home / "gone" / "python"), "args": [], "_provenant_original": {"command": "npx"}}
        self.cursor.write_text(json.dumps(cfg))
        code, out = self.run_cli("doctor", "--json")
        self.assertEqual(code, 1)
        self.assertEqual({c["id"]: c for c in json.loads(out)["checks"]}["client:cursor"]["status"], "fail")


if __name__ == "__main__":
    unittest.main()
