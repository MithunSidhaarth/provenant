"""Tests for the user-facing maintenance commands; all network/process calls are mocked."""
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch, MagicMock


class MaintenanceTests(unittest.TestCase):
    def test_dashboard_opens_browser_by_default(self):
        with patch("agentshield.server.main", return_value=0) as main:
            from agentshield.maintenance import dashboard
            self.assertEqual(dashboard([]), 0)
            main.assert_called_once_with(["--open"])

    def test_server_main_accepts_dashboard_arguments(self):
        from agentshield import server
        httpd = MagicMock()
        with patch.object(server, "serve", return_value=httpd) as serve:
            with patch("webbrowser.open") as open_browser:
                server.main(["--host", "127.0.0.1", "--port", "8766", "--open"])
        serve.assert_called_once_with("127.0.0.1", 8766)
        open_browser.assert_called_once_with("http://127.0.0.1:8766/")
        httpd.serve_forever.assert_called_once()

    def test_update_uses_active_python_and_correct_distribution(self):
        result = MagicMock(returncode=0)
        with patch("agentshield.maintenance.subprocess.run", return_value=result) as run:
            from agentshield.maintenance import update
            self.assertEqual(update([]), 0)
            args = run.call_args.args[0]
            self.assertEqual(args[:3], [__import__("sys").executable, "-m", "pip"])
            self.assertEqual(args[-1], "provenant-agent-shield")
            self.assertIn("--upgrade", args)

    def test_update_check_explains_missing_pypi_package(self):
        result = MagicMock(returncode=1, stdout="", stderr="ERROR: No matching distribution found for provenant-agent-shield")
        out = io.StringIO()
        with patch("agentshield.maintenance.subprocess.run", return_value=result), redirect_stdout(out):
            from agentshield.maintenance import update
            self.assertEqual(update(["--check"]), 1)
        self.assertIn("not published on PyPI", out.getvalue())
        self.assertIn("install.ps1", out.getvalue())

    def test_dashboard_port_in_use_is_a_clear_error(self):
        from agentshield import server
        err = io.StringIO()
        with patch.object(server, "serve", side_effect=OSError(98, "Address already in use")), \
                patch("sys.stderr", err), self.assertRaises(SystemExit) as cm:
            server.main(["--port", "8767"])
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("already running", err.getvalue())

    def test_update_check_does_not_install(self):
        result = MagicMock(returncode=0, stdout="provenant-agent-shield (0.10.0)", stderr="")
        with patch("agentshield.maintenance.subprocess.run", return_value=result) as run:
            from agentshield.maintenance import update
            self.assertEqual(update(["--check"]), 0)
            self.assertIn("index", run.call_args.args[0])
            self.assertNotIn("install", run.call_args.args[0])

    def test_test_reports_all_three_layers(self):
        from agentshield import guard, onboarding
        fake_store = MagicMock()
        fake_store.audit.verify.return_value = {"ok": True, "checked": 4}
        with patch.object(onboarding, "self_test", return_value={"passed": True}), \
             patch.object(onboarding, "doctor", return_value={"ok": True}), \
             patch.object(guard, "Store", return_value=fake_store):
            from agentshield.maintenance import test
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(test(as_json=True), 0)
            self.assertIn('"enforcement"', out.getvalue())
            self.assertIn('"audit"', out.getvalue())


if __name__ == "__main__":
    unittest.main()
