# Changelog

All notable changes. Versions follow the `provenant-agent-shield` package version.

## 0.10.3 (branch `claude/project-thread-if8nxm`, not merged)

Hardening of the enforcement boundary. No new dependencies, no new integrations; every fix has a regression test that fails on 0.10.2.

### Security fixes
- **An agent could switch Provenant off.** `provenant rollback --yes`, `provenant uninstall claude-code` and `provenant unwrap CLIENT` run from an agent's shell (Claude Code `Bash`, or an MCP `run_command`) were allowed. They are now denied, like `approve`, `reject`, `pins reset` and `mail disable` already were.
- **One malformed MCP message killed the proxy.** A `tools/call` (or `initialize`, `prompts/get`) whose `params` was not an object raised outside the fail-closed path and ended the proxy, so every tool of that server disappeared for the session. Each message now fails closed on its own (`-32602`/`-32603`) and the proxy keeps serving.
- **Unsolicited server responses were forwarded.** A server could send a response to an id the client had not used yet; the client would match it to its next `tools/list` and see tools that never went through manifest review. Responses whose id matches no forwarded request are dropped and audited.
- **Calls to tools the server never advertised were evaluated like any other call.** They are now refused before policy evaluation ("unlisted tools never run"), including calls sent before the first `tools/list`.
- **The MCP server dying mid-call hung the agent.** Every in-flight request now gets a JSON-RPC error (allowed calls are reported as "outcome unknown"), later requests are refused with nothing sent, and an `upstream_exit` record is written.
- **Raw secrets were kept in local session state.** Tool output and prompts stored for taint tracking in `~/.provenant/state.db` are now secret-redacted; destinations (hosts, emails) are kept, so taint still works.
- **Claude Code hook timeout failed open.** Claude Code runs a tool when its hook times out (30 s). A PreToolUse decision that takes longer than 20 s now answers `deny` itself.

### Fixed
- `provenant update` said only "ERROR: No matching distribution" because the package is not on PyPI; it now says so and prints the one-line installer.
- `provenant dashboard` on a busy port printed a traceback; it now says the port is in use.
- The simulated MCP gateway answered non-object `params` with `id: null`.

### Tests
- 256 unit and integration tests (246 before), live proxy checks 11/11 (9 before), attacks 225/225 contained, benign 53/53.

## 0.10.2 (merged to main in PR #23)

A same-named 0.10.1 wheel was already published without the dashboard, so these fixes ship as 0.10.2 to make the upgrade visible.

### Fixed
- **Installed `provenant dashboard` crashed** with `FileNotFoundError: .../site-packages/dashboard/index.html`. The wheel did not include the dashboard, policy, scenarios, fixtures or eval data. They now ship as data packages (`provenant_dashboard`, `provenant_policy`, ...), found through `agentshield/resources.py`. Demo audit files no longer get written into site-packages.
- **`provenant mail setup` failed on Windows with `[WinError 5] Access is denied`.** It wrote settings to `HKCU\Environment`, which some machines refuse. Settings now live in `~/.provenant/mail.json` (mode 0600), and the Bolna key is encrypted with DPAPI on Windows. The registry is only read, for old installs.
- Phone alerts: if a saved Bolna agent was deleted, calls now recreate it once instead of failing every time. Network errors include the reason. `call.ps1` failures show the last error line with phone numbers masked.
- The demo's `read_email` result was recorded as live MCP traffic. Demo records are now stamped `source=demo` and are never counted in the live console.
- `provenant rollback --help` performed the rollback, and `wrap --help` read `--help` as a config path. Per-command `--help` now only prints help.
- `provenant log` printed "None" for calls whose arguments were outside the window shown.
- The MCP `serverInfo.version` of `provenant serve` was "dev"; it is now the package version.
- The no-JavaScript fallback on `/getting-started` linked the 0.9.0 wheel.

### Added
- `provenant mail demo [--call]`: a fake phishing email (reserved `.example` domains) goes through the scanner (HIGH), then the injected "email the invoices" call is denied. `--call` places a real, clearly labelled alert call after confirmation.
- `provenant mail test`, `provenant mail call-status ID`, and non-interactive `provenant mail setup --phone ... --agent-id ...`.
- `provenant check Bash "rm -rf ~"` accepts a plain command string, which avoids PowerShell 5.1 JSON quoting problems.
- Operations console: a **Demo scenarios** section that lists demo runs, labelled DEMO, apart from live numbers. Sidebar navigation scrolls, tracks the active section, and supports deep links and back/forward.
- Website motion pass: anime.js page loader, scroll-velocity marquee, scroll-lit statement, hero parallax, section-title reveals, the two-lane attack replay hero and the launch video.
- Hosted site: `/` now serves the product site and `/console` the operations console. Locally, `/` is still the console.
- Docs: QUICKSTART, SECURITY_MODEL, TROUBLESHOOTING, DEMO_RUNBOOK, FINAL_READINESS_AUDIT, FINAL_TEST_REPORT; Mermaid diagrams in ARCHITECTURE.
- Tests: wheel ships and serves the dashboard; only the current release is offered to new users; demo and live separation; subcommand help never runs a command; stale Bolna agent recovery; mail settings without the registry.

## 0.10.0
- Live Guard operations console on `provenant dashboard` (audit-backed numbers only), `provenant test`, `provenant update`, `provenant doctor` improvements.
- Mail security scanner for MCP email results, with optional Bolna phone alerts.
- Distribution renamed to `provenant-agent-shield`.

## 0.9.1
- Windows installer rewritten after the PowerShell 5.1 quote-stripping failure. The wheel is pinned by SHA-256.

## 0.9.0
- Guided onboarding: `setup --client/--yes`, layered `status`, `verify`, `doctor`, `rollback`, `model status/test`, `/getting-started` wizard. Optional advisory classifier (escalate-only, off by default, not trained).

## 0.8.x and earlier
- See the version history table in `CLAUDE.md`: the policy engine, gateway, audit chain, fuzzer and red-team loop (v1 to v5), the dashboard rebuild (v7), the real-tool Guard (v6), the live runtime with SQLite approvals and the gated tool server (v8), and red-team round 2 (225 attacks).
