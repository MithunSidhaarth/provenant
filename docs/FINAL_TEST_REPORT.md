# Final test report (0.10.3, 2026-10-31)

Run in the cloud build session on Linux (Python 3.13.18, Chromium through Playwright), branch `claude/project-thread-if8nxm` off main `000588c`. Nothing was run on Windows or macOS, in GitHub CI, against a real email account, or with a real phone call.

| Check | Command | Result |
|---|---|---|
| Unit and integration tests | `python3 -m unittest discover -s tests -t .` | **257 run, OK, 2 skipped** (PowerShell function tests need `pwsh`) |
| Security evaluation | `python3 evals/run_eval.py` | **Attacks 231/231 contained (DENY 171, REQUIRE_APPROVAL 60), legitimate 53/53, scenarios 32/32, live proxy checks 11/11, exit 0** |
| Decision latency | same, 1,550 evaluations, no model call | p50 0.199 ms, p95 0.83 ms |
| Proxy overhead | same, one `read_file` call direct vs through the proxy, 50 samples after 10 warm-up | p50 about 11 ms (10.8 to 14.2 ms across three runs today); includes SQLite and audit writes; varies with machine load |
| Regression tests fail on the old code | new tests run against 0.10.2's `mcp_proxy.py` and `guard.py` | 4 of the new proxy tests fail on the old code (crash, unlisted tool, unsolicited response, self-disable); the state-redaction test fails without the fix |
| Release build | `python3 scripts/build_release.py --publish-site` | wheel + sdist + SHA256SUMS + SBOM + provenance; `install.ps1` pin updated; only 0.10.3 is published |
| Clean install | new venv outside the repo, `pip install dist/provenant_agent_shield-0.10.3-py3-none-any.whl` | `--version` 0.10.3; `verify` passes; `status` shows installed / engine ready / not configured / not connected; `check Bash "rm -rf ~"` BLOCK; `dashboard` serves `/` and `/api/guard/status` |
| Policy simulator | `provenant policy test` | 32/32 |
| Mail demo | `provenant mail demo` | Scanner HIGH (17); `send_email` to the attacker DENY; no call placed |
| Browser walkthrough | Playwright: `/` at 1440 and 390, `/site.html` at 1440 and 390, `/getting-started` at 390 | all 200, 0 console errors, no horizontal overflow |
| Whitespace | `git diff --check` | clean |

## Bugs fixed in this pass

| # | Severity | Bug | Fix | Test |
|---|---|---|---|---|
| 1 | High | An agent could run `provenant rollback --yes`, `uninstall claude-code` or `unwrap CLIENT` and switch Provenant off | shell rule extended; DENY | `test_guard`, `test_real_proxy`, 3 eval attacks |
| 2 | High | MCP write/delete tools with no file path (`delete_repository`, `delete_records`) were ALLOWed: workspace confinement had nothing to check | REQUIRE_APPROVAL | `test_guard`, 3 eval attacks |
| 3 | High | One `tools/call` with non-object `params` crashed the proxy (every tool of that server gone for the session) | per-message fail-closed errors | `test_real_proxy`, live eval check |
| 4 | Medium | A server response to an id nobody used was forwarded; it could pre-empt a `tools/list` and skip manifest review | dropped and audited | `test_real_proxy` |
| 5 | Medium | Calls to tools never advertised in the session were evaluated like any other call | refused before evaluation | `test_real_proxy`, live eval check |
| 6 | Medium | Upstream server dying mid-call hung the agent or crashed the proxy | errors for every in-flight request, nothing resent | `test_real_proxy` |
| 7 | Medium | Raw secrets from tool output and prompts were stored in `~/.provenant/state.db` | redacted before storing | `test_guard` |
| 8 | Medium | Claude Code runs a tool when its hook times out (30 s); a stuck decision failed open | hook answers deny at 20 s | `test_real_proxy` |
| 9 | Low | `provenant update` gave a bare pip error (not on PyPI); dashboard on a busy port printed a traceback; simulated gateway lost the request id on errors | clear messages; id kept | `test_maintenance` |

## Not tested

- Real Windows (`install.ps1`, `test.bat`), macOS, and the GitHub CI and release workflows (they have never run on GitHub).
- A real Bolna call, phone approval of a held call, real Gmail with `mail watch`.
- Claude Code subagents and the hook's `ask` decision under `bypassPermissions`; third-party MCP servers (npx downloads are blocked in the build machine).
- The hosted site after merge (deploys only from main). The site bundle was not rebuilt: only the install version strings in `dashboard/start.js` and `dashboard/getting-started.html` were changed to 0.10.3.

## Previous pass: 0.10.2, 2026-10-30

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
