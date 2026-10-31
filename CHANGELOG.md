# Changelog

All notable changes. Versions follow the `provenant-agent-shield` package version.

## 0.10.2 (unreleased, branch `feat/live-guard-dashboard`)

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
