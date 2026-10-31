# Quickstart

Five minutes from nothing to an agent whose tool calls go through Provenant. Everything here runs locally. Nothing is sent to a server we run.

## 1. Install (current release: 0.10.2)

You need Python 3.10 or newer.

```powershell
# Windows (PowerShell): downloads the 0.10.2 wheel, checks its SHA-256, installs it for your user
irm https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.ps1 | iex
```

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.sh | sh
```

The installers only ever fetch the current wheel (`dist/provenant_agent_shield-0.10.2-py3-none-any.whl`). A test (`tests/test_installer.py`) fails the build if any install path names an older version or if an older wheel is still published.

From a clone you can skip installing: `python3 provenant.py <command>` (or `provenant.bat <command>` on Windows).

## 2. Check the engine on its own

```bash
provenant --version      # provenant 0.10.2
provenant verify         # safe self-test: a destructive command is blocked, a held call is held, the audit chain is intact
provenant doctor         # environment checks (PATH, resources, state folder, policy)
```

`verify` proves the local engine works. It does **not** prove that your AI client is routed through it; `status` tells you that.

## 3. Protect your AI clients

```bash
provenant setup --dry-run   # show the plan, change nothing
provenant setup             # asks, backs up each config, then wraps MCP servers and installs the Claude Code hook
provenant status            # installed / engine / configured / connected / verified
```

- **MCP clients** (Claude Desktop, Cursor, Windsurf, VS Code): each MCP server is relaunched through `provenant proxy`. Restart the client afterwards.
- **Claude Code**: a PreToolUse / PostToolUse / UserPromptSubmit hook in `~/.claude/settings.json`.

`status` reports a client as **connected** only after real audit traffic from it has been seen. Configured is not the same as working.

## 4. Watch it work

```bash
provenant dashboard     # local operations console at http://127.0.0.1:8765/
provenant log -f        # live feed: ok / BLOCK / HOLD / TAINT
provenant approve       # decide held calls; must be typed by a person at a terminal
```

The dashboard counts real, audit-backed activity only. Demo runs are listed separately under **Demo scenarios**.

## 5. Optional: a gated MCP tool server

```bash
provenant serve --workspace .          # stdio MCP server: read_file, list_directory, search_text, run_tests, write_file, http_get
provenant config claude-desktop        # prints the mcpServers snippet
```

Every call is checked, a single-use grant is redeemed, and only then does the tool run. `run_command` exists only with `--allow-shell`.

## 6. Optional: email phishing alerts by phone

```bash
provenant mail setup                   # Bolna API key (stored in ~/.provenant/mail.json, DPAPI-encrypted on Windows) + your phone
provenant mail demo                    # fake phishing email: scanner verdict, then the injected send is blocked. No call.
provenant mail test                    # one real test call (asks first)
provenant mail demo --call             # the demo, then a real alert call about the fake email (asks first)
provenant mail call-status <id>        # queued / ringing / completed / failed
```

On a Bolna trial account the phone number must be verified in the Bolna dashboard first.

## Undo everything

```bash
provenant rollback --dry-run && provenant rollback
provenant uninstall claude-code
python -m pip uninstall provenant-agent-shield
```

Your state (audit chain, approvals, settings) stays in `~/.provenant` until you delete it.

Problems? See [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
