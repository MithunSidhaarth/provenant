# Provenant 0.9.0 update log

## Shortest path for a new user
1. Install: `irm https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.ps1 | iex` (Windows PowerShell) or `curl -fsSL https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.sh | sh` (macOS/Linux). Needs Python 3.10+.
2. `provenant setup` (shows a plan, asks first; `--client claude-code` to pick one).
3. `provenant verify` (safe enforcement test), then `provenant status`. "Connected" appears only after the client makes a real tool call.
If `provenant` is not found: `py -m provenant ...` / `python3 -m provenant ...`.

## Done
- CLI: setup (consent, --yes, --client, read-back), status layers + `--json`, verify self-test, doctor, rollback, model status/test.
- Optional model classifier: advisory, escalate-only, opt-in via policy `model_assist`; secrets redacted; strict schema; fail-safe. Not trained.
- Packaging: `python -m provenant`, wheel tested in a fresh venv outside the repo (tests/test_packaging.py).
- Downloads: public GitHub URLs (the 0.8.0 Vercel link returned a login page); `scripts/check_download.py`.
- Site: new hero copy, `/getting-started` wizard (OS, shell, client, method, mode), contextual troubleshooting, honest model status.
- `model/`: dataset build/validate (group splits), QLoRA script, evaluator, model card template. Nothing trained.

## Tests (run here, Linux, Python 3.13)
- Unit: 193/193. Eval: 128/128 attacks, 35/35 benign, 9/9 live.

## Not done / blockers
- Not deployed; download URL goes live only after merge to main. Then run `python3 scripts/check_download.py --install`.
- install.ps1 never run on real Windows; Cursor/Windsurf untested in the real apps.
- No browser/accessibility pass of the new page yet; no model trained or benchmarked.

## 0.9.1: Windows installer repair
- Root cause: Windows PowerShell 5.1 strips double quotes from arguments passed to native programs. The 0.9.0 installer
  ran `python -c 'import sys; print(".".join(...))'`, which Python received as `print(..join(...))` (SyntaxError); the failed
  command's null output then hit `.Trim()` ("cannot call a method on a null-valued expression"). The served script was
  identical to the repository's; it was not stale or cached. PowerShell 7.3+ passes quotes through, so 7 did not show it.
- install.ps1 rewritten: quote-free Python snippets, exit code checked after every native call, candidate interpreters
  probed and validated, wheel validated (zip, metadata version, entry point, SHA-256 pinned by build_release.py), import and
  wrapper verified, PATH deduplicated, no `exit` under iex. See tests/test_installer.py and the `installer-windows` CI job.
- Not run on real Windows from here. The `installer-windows` job has not executed yet.

## 0.9.2
- install.ps1: the PATH step is best-effort (a refused registry write no longer aborts the install) and function cleanup works on Windows PowerShell 5.1. Both found by the first real Windows run.
- Antigravity added as an **experimental** client (`provenant setup --client antigravity`, `/getting-started`). Path `~/.gemini/config/mcp_config.json` and the `mcpServers` format are from Google's Antigravity MCP docs; tested only on sample configs, not in the real app. Remote `serverUrl` servers are not proxied.

## 0.9.2 installer follow-up (hidden prompt)
- Real Windows run: step 5 looked hung. Cause: `& $cmd setup` ran inside `Pv-Main`, whose output is captured (`@(Pv-Main)[-1]`), so setup's text and its "Apply these changes? [Y/n]" prompt were swallowed while it waited for input. The installer now runs only `setup --dry-run` (no stdin, 30 s limit) and tells the user to run `provenant setup` themselves. Guarded by a static test (no bare native command in `Pv-Main`).

## 0.10.3: boundary hardening (2026-10-31)
- Fixed: agents could switch Provenant off (`provenant rollback/uninstall/unwrap`); MCP write/delete tools with no file path were allowed; one malformed MCP message crashed the proxy; unsolicited server responses and unadvertised tools were not refused; a dying MCP server hung the agent; raw secrets were kept in session state; the Claude Code hook failed open on timeout.
- New: docs/COVERAGE.md (what each boundary observes, blocks, holds and misses). No new dependencies, no per-product integrations.
- Tests: 257/257 (2 skipped), eval 231/231 attacks, 53/53 benign, 11/11 live checks. Details: docs/FINAL_TEST_REPORT.md.
