# Final readiness audit (2026-10-30, branch `feat/live-guard-dashboard`, version 0.10.2)

Scope: everything a judge or a new user touches, inspected and exercised in a Linux cloud container (Python 3.13, Chromium via Playwright). Windows-only paths were checked by reading code and tests, not by running them on Windows. Test evidence is in [FINAL_TEST_REPORT.md](FINAL_TEST_REPORT.md).

**Overall: ready for the demo, with three items that need the laptop first** (see "Blockers").

## Findings and what was done

| Area | Finding | Severity | Status |
|---|---|---|---|
| Packaging | An installed `provenant dashboard` crashed (`FileNotFoundError ... site-packages/dashboard/index.html`). The wheel had no dashboard, policy, scenarios, fixtures or eval data. The packaging test copied the repo but did not exercise the dashboard. | High | Fixed: data packages + `resources.py`; tests serve `/`, `/ops.js`, `/site.html` and the APIs from a clean venv |
| Packaging | A 0.10.1 wheel without the dashboard is already on main, so a fixed build under the same number could never reach existing users | High | Version bumped to 0.10.2; installers, site, onboarding and `latest.json` all name 0.10.2; old wheels removed from `dist/` and the download folder |
| Packaging | Demo audits were written into the repo or site-packages | Medium | Fixed: `~/.provenant/demo-audit` when installed |
| Phone alerts | `provenant mail setup` hit `[WinError 5] Access is denied` writing `HKCU\Environment` | High | Fixed: settings in `~/.provenant/mail.json` (0600, DPAPI on Windows); registry read-only |
| Phone alerts | A deleted Bolna agent made every later call fail; network errors only gave a class name; no way to follow a call | Medium | Fixed: one automatic re-create, error reasons, `mail call-status`, live status follow after placing |
| Phone alerts | No demo scenario for judges | Feature | Added `provenant mail demo [--call]` on a fake `.example` phish |
| Dashboard | Demo `read_email` result was stamped `source=mcp, mode=live`, so the console would count a fake event as real MCP traffic | High (truthfulness) | Fixed at the source (`ingest_output(source=)`), server also excludes the `mail-demo` session; demo runs shown in a labelled **Demo scenarios** section |
| Dashboard | Sidebar navigation, active state, deep links, back/forward | Check | Verified at 1440, 820 and 390 px: scrolls, active follows, deep link works, 0 console errors, no horizontal overflow |
| CLI | `provenant rollback --help` performed the rollback | High | Fixed: per-command `--help` only prints help; regression test |
| CLI | `wrap --help` read `--help` as a config path; `uninstall --help` exited 2; `log` printed "None" | Low | Fixed |
| CLI | `provenant check Bash '{"command":...}'` breaks under PowerShell 5.1 quoting | Medium | `check` accepts a plain command string |
| MCP | `provenant serve` reported serverInfo version "dev" | Low | Fixed: reports 0.10.2 |
| MCP | Proxy and gated server behaviour | Check | Clean-install stdio session: initialize, tools/list, allowed read, path escape held, `.env` write denied. Proxy covered by `test_real_proxy` and 9/9 live eval checks |
| Onboarding | `/getting-started` no-JavaScript fallback linked the 0.9.0 wheel | Medium | Fixed; a test now fails if any install path names an old version or an old wheel is published |
| Website | Hosted `/` would have shown the local-only ops console | Medium | `vercel.json`: `/` serves the product site, `/console` the console. Takes effect on the next deploy from main |
| Docs | No quickstart, security model, troubleshooting, demo runbook or changelog | Medium | Written; README links them |

## Security assessment

- The deterministic policy remains the only decision point; the advisory classifier is still escalate-only and off by default. No change in this pass weakens a rule. The red-team corpus is unchanged and still fully contained (225/225), with no false positives (53/53).
- New attack surface reviewed:
  - `mail.json` holds the Bolna key. It is mode 0600, encrypted with DPAPI on Windows, and plain on macOS/Linux (documented). It is never printed, and `mail status` masks the phone.
  - `provenant mail demo --call` needs setup, then `--yes` or a TTY confirmation, and its spoken text has no links or body.
  - `/api/guard/log` now returns the last 40 demo records with the same masking as live records.
- The dashboard still never approves; approvals stay terminal-only.

## Blockers (need the laptop or mithun)

1. **A real test call**, which can't be done from the cloud (api.bolna.ai is blocked here): `provenant mail setup`, then `provenant mail test`, then `provenant mail call-status <id>`. On a trial account the number must be verified in Bolna.
2. **Windows run** of `test.bat` and the one-line installer on the laptop (never executed on Windows by us).
3. **Merge and deploy are mithun's call.** PR #23 is not merged; the hosted site keeps its current routing until a deploy from main.

## Not changed on purpose

- Paraphrase gap in value-based provenance (open decision 1 in CLAUDE.md) is documented, not fixed.
- Phone approval for held calls (`voice.py`) still untested with a real call; labelled as such everywhere.
