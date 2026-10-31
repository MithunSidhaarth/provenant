# Final test report (0.10.2, 2026-10-30)

Everything below was run in this session on Linux (Python 3.13.17, Chromium through Playwright), on branch `feat/live-guard-dashboard`. Nothing was run on Windows or macOS, and no real phone call was placed (api.bolna.ai is not reachable from the build machine).

## Results

| Check | Command | Result |
|---|---|---|
| Unit and integration tests | `python3 -m unittest discover -s tests -t .` | **235 run, OK, 2 skipped** (the two PowerShell function tests need `pwsh`, which is not installed here; CI runs them) |
| Security evaluation | `python3 evals/run_eval.py` | **Attacks 225/225 contained, legitimate 53/53, live proxy checks 9/9, exit 0.** Policy p50 0.152 ms; proxy overhead p50 22.7 ms on this run (13.9 to 14.7 ms on earlier runs today; it varies with machine load) |
| Policy scenarios | `provenant policy test` | 32/32 |
| Whitespace | `git diff --check` | clean |
| Clean install of the release wheel | new venv, `pip install --no-index dist/provenant_agent_shield-0.10.2-py3-none-any.whl` | `provenant --version` prints 0.10.2; `provenant verify --json` passed; the dashboard resolves to `site-packages/provenant_dashboard` |
| Installed dashboard | `tests/test_packaging.py` | `/`, `/ops.js`, `/site.html`, `/api/scenarios`, `/api/guard/status` all 200 from a wheel installed outside the repo; no audit files written into the venv |
| Every CLI command from a clean install | `--version --help status [--json] verify doctor setup --dry-run check log policy test/lint model status mail status/demo/test audit verify config approve rollback/wrap/uninstall/mail/serve --help` | All exit as expected. `mail test` without setup exits 2 with "Run 'provenant mail setup' first". `approve` without a terminal is refused (by design) |
| MCP gated server | stdio session against the installed `provenant serve` | initialize OK (version 0.10.2 after the fix); tools/list returns 6 tools; `read_file a.txt` returns the file; `../../etc/passwd` is REQUIRE_APPROVAL; writing `.env` is DENY |
| MCP proxy | `tests/test_real_proxy.py` + 9 live eval checks | pass |
| Mail demo | `provenant mail demo` | Scanner HIGH (score 17, 7 reasons); `send_email` to the attacker is DENY; no call placed |
| Dashboard in a browser | Playwright at 1440, 820 and 390 px | Every sidebar item scrolls to its section and becomes active; `#approvals` deep link opens there; back works; **0 console errors**; no horizontal overflow. `/site.html` and `/getting-started`: 0 console errors, no overflow |
| Live vs demo separation | `/api/guard/log` after `provenant mail demo` | `total` 0 live, 8 demo records listed separately |
| Deck | `validate.py` on the pptx, LibreOffice render | All validations passed; 11 slides checked visually |

## Regression tests added in this pass

- `test_packaging`: wheel ships the dashboard and demo data; the installed dashboard serves from the wheel.
- `test_installer`: new users are only offered the current release (every install path and the published folders).
- `test_mail_security`: settings without the registry (0600, setup without a TTY); demo flags HIGH and DENY without dialing; `--call` needs setup and confirmation, and the spoken text has no link or body; a deleted Bolna agent is re-created once; demo records are listed apart from live activity.
- `test_cli`: subcommand `--help` never runs the command and never touches client configs.

## Not tested (needs the laptop)

- A real Bolna call (`provenant mail test`, `provenant mail demo --call`).
- `install.ps1`, `test.bat` and DPAPI encryption on real Windows.
- Phone approval of a held call (`voice.py`).
- The hosted site after the `vercel.json` change (deploys only from main).
- `scripts/check_download.py` against main: it currently reports `sha256_match: false` because main still serves the old 0.10.1 wheel. It is expected to pass after PR #23 is merged.
