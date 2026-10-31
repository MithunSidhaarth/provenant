# Troubleshooting

Start with `provenant doctor`. It checks the command on PATH, the bundled resources, the state folder, the policy and the audit chain, and it says what to run next.

## Install

**`provenant` is not recognised after installing (Windows).** The installer puts the command in your user Scripts folder. Open a new PowerShell window. If it is still missing, run `python -m provenant setup`; every command works that way too. The installer prints the exact folder to add to PATH when it could not add it itself.

**Python is a Microsoft Store install and `python` opens the Store.** Use `py -3`, or the full path `%LOCALAPPDATA%\Microsoft\WindowsApps\python3.11.exe`. The `.bat` launchers probe both.

**The download is an HTML page, not a wheel.** You followed an old link. Use the one-line installer or the Download button on the site; both fetch `provenant_agent_shield-0.10.3-py3-none-any.whl` and check its SHA-256.

**`provenant dashboard` fails with `FileNotFoundError ... dashboard/index.html`.** You have a 0.10.1 or earlier wheel, which did not include the dashboard files. Install 0.10.2 (the one-line installer, or `provenant update` once it is on PyPI).

## Setup and clients

**`status` says configured but not connected.** Connected means real audit traffic has been seen from that client. Restart the client (Claude Desktop, Cursor and others only re-read their config at start), use one tool, then run `provenant status` again.

**The Claude Code hook shows "Not detected" on the dashboard.** Run `provenant install claude-code` (or `--project` for one repo) and restart Claude Code. Check with `provenant status`.

**I want to undo everything.** Run `provenant rollback --dry-run`, then `provenant rollback`. Every config was backed up before it was changed.

**`provenant approve` says "refused: approvals must be typed by a person at a terminal".** This is deliberate: an agent running commands has no terminal, so it cannot approve its own held call. Run it yourself in a normal terminal window.

## Phone alerts (Bolna)

**`Could not save user settings: [WinError 5] Access is denied`.** Fixed in 0.10.2. Older versions wrote the settings to the registry (`HKCU\Environment`), which some machines refuse. Settings now live in `~/.provenant/mail.json` and the API key is encrypted with DPAPI. Update, then run `provenant mail setup` again.

**`Call failed to start: Bolna API returned HTTP 4xx`.** Check, in order:
1. The API key is correct (`provenant mail setup` again).
2. On a Bolna **trial** account, the phone number must be verified in the Bolna dashboard before it can be called.
3. The account has credit.
4. The number is in international format, such as `+919876543210`. Spaces and dashes are removed for you.

If the agent saved by an earlier setup was deleted in Bolna, the next call creates a new one automatically.

**The call was queued but the phone did not ring.** Run `provenant mail call-status <execution id>`. `failed` or `no-answer` with a reason usually means an unverified number or a carrier block (DND numbers in India).

**`Bolna API request failed: URLError`.** The machine cannot reach `api.bolna.ai`, usually because of a proxy or firewall. The message includes the underlying reason.

## Dashboard

**The page is blank or the top-right badge says GUARD DISCONNECTED.** The local server is not running. Start it with `provenant dashboard`, then reload `http://127.0.0.1:8765/`.

**Port 8765 is in use.** Another dashboard is already running. Open the existing tab, or stop the other process.

**The numbers stay at 0.** The console counts real, audit-backed activity only. `provenant mail demo` and other demo runs appear under **Demo scenarios** instead. Start a protected client and use a tool.

## Audit

**`audit verify` reports a bad sequence number.** The log was edited or partly written. Keep a copy of `~/.provenant/audit*.jsonl` for investigation, then compare against your last `provenant audit checkpoint`.
