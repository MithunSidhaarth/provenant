"""install.ps1 regressions. The 0.9.0 failure: Windows PowerShell 5.1 strips double quotes from native-command
arguments, so print(".".join(...)) reached Python as print(..join(...)) and the version came back null.

What runs where: the static and Python-level checks below run everywhere. The PowerShell function tests run only
when `pwsh` is installed (CI's Linux runner has it). The end-to-end install on Windows PowerShell 5.1 and 7 runs only
in the `installer-windows` CI job: nothing in this file proves the installer ran on real Windows."""
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PS1 = (ROOT / "install.ps1").read_text(encoding="utf-8")
PWSH = shutil.which("pwsh")


def snippets() -> dict:
    return dict(re.findall(r"\$(Pv\w+Code) = '([^']*)'", PS1))


def wheel_check_script() -> str:
    return re.search(r"\$PvWheelCheckCode = @'\n(.*?)\n'@", PS1, re.S).group(1)


def ps51_args(code: str) -> str:
    """What Windows PowerShell 5.1 hands to a native program for a -c argument: embedded double quotes vanish."""
    return code.replace('"', "")


class Source(unittest.TestCase):
    def test_ascii_only_and_no_bare_exit(self):
        PS1.encode("ascii")                                    # irm decodes by header; stay encoding-proof
        for i, line in enumerate(PS1.splitlines(), 1):
            if re.search(r"(^\s*|\{\s*)exit\s", line) and not line.lstrip().startswith("#"):
                self.assertIn("$PSCommandPath", PS1.splitlines()[i - 1], f"line {i}: exit would close an iex session")

    def test_python_snippets_survive_powershell_51_quoting(self):
        found = snippets()
        self.assertEqual(set(found), {"PvProbeCode", "PvImportCode"})
        for name, code in found.items():
            self.assertNotIn('"', code, name)
            compile(ps51_args(code), name, "exec")
        probe = subprocess.run([sys.executable, "-c", ps51_args(found["PvProbeCode"])], capture_output=True, text=True)
        lines = probe.stdout.split("\n")
        self.assertEqual(probe.returncode, 0)
        self.assertTrue(Path(lines[0]).is_file())
        v = sys.version_info
        self.assertEqual(int(lines[1]), v[0] * 10000 + v[1] * 100 + v[2])
        self.assertIn(lines[2], ("0", "1"))

    def test_the_0_9_0_expression_really_broke_under_51_quoting(self):
        old = 'import sys; print(".".join(map(str, sys.version_info[:3])))'
        with self.assertRaises(SyntaxError):
            compile(ps51_args(old), "old", "exec")
        r = subprocess.run([sys.executable, "-c", ps51_args(old)], capture_output=True, text=True)
        self.assertIn("SyntaxError", r.stderr)                 # the exact message the user reported
        self.assertNotIn("join(map(str", "".join(snippets().values()))

    def test_no_native_c_argument_with_double_quotes_anywhere(self):
        for path in [ROOT / "install.ps1", *ROOT.glob("*.ps1")]:
            for m in re.finditer(r"""-c\s+'([^']*)'""", path.read_text(encoding="utf-8")):
                self.assertNotIn('"', m.group(1), f"{path.name}: {m.group(1)[:50]}")

    def test_versions_agree_everywhere(self):
        version = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)
        self.assertIn(f"$PvVersion = '{version}'", PS1)
        self.assertIn(f'VERSION="{version}"', (ROOT / "install.sh").read_text())
        self.assertEqual(json.loads((ROOT / "web/src/onboarding.json").read_text())["version"], version)
        self.assertEqual(json.loads((ROOT / "dashboard/download/latest.json").read_text())["version"], version)

    def test_new_users_are_only_offered_the_current_release(self):
        # Every install path a new user can copy names the current wheel, and only the current wheel is published.
        version = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)
        for rel in ("dashboard/getting-started.html", "web/src/onboarding.json", "web/src/Site.jsx", "dashboard/site.js",
                    "dashboard/start.js", "README.md", "docs/QUICKSTART.md"):
            f = ROOT / rel
            if f.is_file():
                for found in re.findall(r"provenant(?:_agent_shield)?-(\d+\.\d+\.\d+)-py3", f.read_text(encoding="utf-8")):
                    self.assertEqual(found, version, rel)
        for d in ("dist", "dashboard/download"):
            wheels = {w.name for w in (ROOT / d).glob("*.whl")}
            self.assertEqual(wheels, {f"provenant_agent_shield-{version}-py3-none-any.whl"}, d)

    def test_pinned_checksum_matches_the_published_wheel(self):
        version = re.search(r"\$PvVersion = '([^']+)'", PS1).group(1)
        wheel = ROOT / "dist" / f"provenant_agent_shield-{version}-py3-none-any.whl"
        self.assertTrue(wheel.exists(), "run scripts/build_release.py --publish-site")
        pinned = re.search(r"\$PvWheelSha256 = '([0-9a-f]{64})'", PS1).group(1)
        self.assertEqual(pinned, hashlib.sha256(wheel.read_bytes()).hexdigest())
        self.assertEqual((ROOT / "dashboard/download" / wheel.name).read_bytes(), wheel.read_bytes())

    def test_path_step_and_cleanup_cannot_abort_the_install(self):
        # Seen on a real Windows PowerShell 5.1 run: registry SetValue was refused (fatal), and
        # Get-ChildItem -Path function: -Name 'Pv-*' is not supported by the function provider.
        self.assertNotIn("Get-ChildItem -Path function:", PS1)
        self.assertIn("Remove-Item -Path 'function:Pv-*'", PS1)
        body = PS1[PS1.index("function Pv-SetUserPath"):PS1.index("# ---- the installer")]
        for call in re.finditer(r"\$pathResult = Pv-SetUserPath", PS1):
            self.assertNotIn("return 1", PS1[call.start(): call.start() + 400].split("Pv-Step 5")[0])
        self.assertIn("return \"failed:", body)

    def test_main_never_runs_a_bare_native_command(self):
        # 0.9.2 ran `& $cmd setup` inside Pv-Main, whose output is captured by `@(Pv-Main)[-1]`: setup's prompt was
        # swallowed and the install appeared to hang. Native programs may only run through Pv-Native / Pv-RunTimed.
        main = PS1[PS1.index("function Pv-Main"):PS1.index("# PROVENANT_INSTALL_LIB")]
        for i, line in enumerate(main.splitlines(), 1):
            self.assertNotRegex(line, r"^\s*&\s", f"Pv-Main line {i}: {line.strip()}")
        self.assertNotIn(" setup`" , main)
        self.assertIn("setup --dry-run", main)
        self.assertIn("RedirectStandardInput = $true", PS1)          # no console input for child processes

    def test_installer_never_weakens_security(self):
        for bad in ("SkipCertificateCheck", "ServerCertificateValidationCallback", "-ExecutionPolicy", "Set-ExecutionPolicy",
                    "Invoke-Expression", "RunAs", "'Machine'"):
            self.assertNotIn(bad, PS1)


class WheelCheck(unittest.TestCase):
    """The validation script the installer runs with the chosen Python, exercised directly."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.script = self.dir / "check.py"
        self.script.write_text(wheel_check_script())
        self.version = re.search(r"\$PvVersion = '([^']+)'", PS1).group(1)
        self.good = ROOT / "dist" / f"provenant_agent_shield-{self.version}-py3-none-any.whl"

    def tearDown(self):
        self.tmp.cleanup()

    def check(self, path, version=None):
        r = subprocess.run([sys.executable, "-I", str(self.script), str(path), version or self.version],
                           capture_output=True, text=True)
        return r.returncode, r.stdout.strip()

    def fake_wheel(self, name, files):
        p = self.dir / name
        with zipfile.ZipFile(p, "w") as z:
            for k, v in files.items():
                z.writestr(k, v)
        return p

    def test_real_wheel_passes(self):
        self.assertEqual(self.check(self.good), (0, "ok"))

    def test_html_login_page_with_status_200_is_rejected(self):
        p = self.dir / "page.whl"
        p.write_text("<!doctype html><html><title>Vercel Authentication</title></html>")
        code, out = self.check(p)
        self.assertEqual(code, 2)
        self.assertIn("not a wheel", out)

    def test_truncated_and_corrupt_wheels_are_rejected(self):
        data = self.good.read_bytes()
        for n, blob in (("trunc.whl", data[: len(data) // 2]), ("empty.whl", b""), ("junk.whl", b"PK\x03\x04" + b"x" * 50)):
            p = self.dir / n
            p.write_bytes(blob)
            self.assertEqual(self.check(p)[0], 2, n)

    def test_wrong_version_is_rejected(self):
        code, out = self.check(self.good, "9.9.9")
        self.assertEqual(code, 2)
        self.assertIn("this installer installs 9.9.9", out)

    def test_wheel_without_required_files_is_rejected(self):
        p = self.fake_wheel("x-0-py3-none-any.whl", {"x-0.dist-info/METADATA": f"Name: x\nVersion: {self.version}\n"})
        code, out = self.check(p)
        self.assertEqual(code, 2)
        self.assertIn("missing required files", out)

    def test_missing_file(self):
        self.assertNotEqual(self.check(self.dir / "nope.whl")[0], 0)


@unittest.skipUnless(PWSH, "pwsh is not installed here; these run in CI")
class PowerShellFunctions(unittest.TestCase):
    def run_ps(self, body: str) -> str:
        env = dict(os.environ, PROVENANT_INSTALL_LIB="1")
        r = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", f". '{ROOT / 'install.ps1'}'; {body}"],
                           capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r.stdout.strip()

    def test_path_handling(self):
        self.assertEqual(self.run_ps(r"Pv-AddToPath '' 'C:\x'"), r"C:\x")
        self.assertEqual(self.run_ps(r"Pv-AddToPath 'C:\a;C:\X\' 'C:\x'"), "C:\\a;C:\\X\\")        # already there: unchanged
        self.assertEqual(self.run_ps(r"Pv-AddToPath 'C:\a;;' 'C:\b'"), r"C:\a;C:\b")
        self.assertEqual(self.run_ps(r"Pv-AddToPath 'C:\a' 'C:\Users\Jo Doe\.provenant\bin'"), r"C:\a;C:\Users\Jo Doe\.provenant\bin")
        self.assertEqual(self.run_ps(r"$p = Pv-AddToPath 'C:\a' 'C:\b'; Pv-AddToPath $p 'C:\b'"), r"C:\a;C:\b")   # repeat run

    def interpreter(self, d: Path, name: str, body: str) -> str:
        d.mkdir(parents=True, exist_ok=True)
        p = d / name
        p.write_text("#!/bin/sh\n" + body + "\n")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
        return str(p)

    def find(self, paths):
        arr = ",".join("'" + p.replace("'", "''") + "'" for p in paths)
        return self.run_ps("$c = @(); foreach ($p in @(" + arr + ")) { $c += ,@($p, @()) }; $r = Pv-FindPython $c; "
                           "if ($r.Python) { $r.Python.Version } else { 'none:' + ($r.Rejected -join '|') }")

    def test_python_discovery(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t) / "Jo Doe" / "Python 312"
            good = self.interpreter(d, "python", r"printf '%s\n31205\n0\n' \"$0\"")
            old = self.interpreter(d, "py8", r"printf '%s\n30800\n0\n' \"$0\"")
            fail = self.interpreter(d, "fail", "exit 1")
            junk = self.interpreter(d, "junk", "echo hello")
            empty = self.interpreter(d, "empty", "exit 0")
            self.assertEqual(self.find([good]), "3.12.5")
            self.assertEqual(self.find([fail, junk, empty, str(d / "missing"), good]), "3.12.5")
            self.assertEqual(self.find([old, good]), "3.12.5")
            self.assertEqual(self.find([fail, junk, empty, str(d / "missing")]), "none:")
            self.assertTrue(self.find([old]).startswith("none:Python 3.8.0 at "))


if __name__ == "__main__":
    unittest.main()
