# Provenant Guard: real blocking between agents and real tools

The dashboard, fuzzer and scenarios prove the design inside a simulated world. **Provenant Guard** puts the same design in front of tools that really run: shell commands, file reads and writes, web fetches, and any MCP server's tools. It is a small local program with no dependencies beyond Python 3.10+. It works on Windows, macOS and Linux.

There are two enforcement points, sharing one deterministic policy, one approval queue and one hash-chained audit log:

```
 Claude Desktop / Cursor / Windsurf / VS Code / any MCP agent
        │  stdio JSON-RPC
        ▼
 provenant proxy ──Guard──▶ ALLOW: forwarded to the real MCP server (launched by the proxy)
                         ├─ REQUIRE_APPROVAL: held, nothing forwarded, a human approves once
                         └─ DENY: answered by the proxy, the server never sees it

 Claude Code ──PreToolUse hook──▶ Guard ──▶ deny | ask (Claude Code's own human prompt) | silent
             ──PostToolUse hook──▶ outputs recorded as untrusted (taint + injection flags)
             ──UserPromptSubmit──▶ the user's own words recorded as trusted
```

## Install (one minute)

```bash
git clone https://github.com/MithunSidhaarth/provenant && cd provenant
python3 provenant.py setup          # Windows: provenant.bat setup
```

`setup` finds the Claude Desktop, Cursor and Windsurf configs and routes every stdio MCP server in them through the proxy. It also installs the Claude Code hooks in `~/.claude/settings.json` when Claude Code is present. Every config it edits gets a timestamped backup. Each wrapped entry keeps its original command, so `provenant unwrap <client>` and `provenant uninstall claude-code` restore everything.

Alternatively, `pip install .` gives you a `provenant` command with the same subcommands.

Targeted commands:

```bash
provenant wrap claude-desktop | cursor | windsurf | vscode | claude-code-project | path/to/config.json
provenant install claude-code [--project]
provenant status                # what is protected, policy version, audit chain health, pending approvals
provenant log -f                # live feed:  ok / BLOCK / HOLD / TAINT, one line per decision
provenant pending               # held calls
provenant approve appr_xxx      # must be typed at a terminal by a person; single use, bound to the exact call
provenant check Bash '{"command":"rm -rf ~"}'    # dry-run a call through the policy
provenant verify                # recompute the audit hash chain
provenant policy init           # copy the built-in policy to ~/.provenant/policy.json to customise it
provenant pins reset [server]   # re-approve tool definitions after a legitimate server upgrade
```

## What it decides (built-in policy `agentshield/guard_policy.json`)

| Area | DENY | REQUIRE_APPROVAL | ALLOW |
|---|---|---|---|
| Shell | `rm -rf` of root, home or the whole workspace; disk formatting; fork bombs; `curl … \| sh`; encoded payloads piped to a shell; reverse shells; uploading local files; force-push; shutdown; destructive Windows commands (`format`, `Remove-Item -Recurse C:\`, `vssadmin delete shadows`); erasing history; reading credential files; approving its own held calls | other recursive deletes, installing packages, `git push` or `reset --hard`, publishing, `sudo`, ssh, killing processes, dumping env vars, POSTing data | everything else (`ls`, `git status`, running tests …) |
| Files | credential files (`.env`, `.ssh`, `.aws`, `*.pem`, `id_rsa` …); writing outside the workspace; touching Provenant's own policy, state or the Claude Code settings | reading outside the workspace; writing CI workflows, shell profiles or `authorized_keys` | reads and writes inside the workspace |
| Network | localhost, private ranges, raw IPs, cloud metadata (SSRF) | hosts not on the allow-list | allow-listed hosts |
| Secrets | API keys, tokens, private keys, SSNs or card numbers in shell, network or send arguments | the same in file content | |
| Provenance | a destination (host or email) that appears only in content the agent read, not in the user's words | any side effect after the session read content with injection indicators | |
| Tools | | send/post/publish tools; tools the policy cannot classify | read/list/search tools |
| MCP manifests | a tool whose definition changed after it was first pinned ("rug pull"), or whose description carries an injection, is withheld and its calls refused | | |

As in the simulated engine, the most restrictive finding wins. Malformed calls, rule errors, unreadable hook input and an unloadable policy all yield DENY. A human approval can lift REQUIRE_APPROVAL but never DENY.

## State and audit

Everything lives in `~/.provenant` (override with `PROVENANT_HOME`):

- `audit.jsonl`: one hash chain shared by every proxy and hook process. Appends happen under a cross-process lock, so parallel tool calls extend one chain instead of forking it. Entries are MAC'd with `key`, which is created once with mode 0600 and never committed.
- `sessions/`: per-session trusted user text, untrusted text and injection flags.
- `approvals.json`, `pins/`, and an optional `policy.json` override.

The whole folder is a protected path, so an agent cannot edit the policy, the approvals or the pins through any tool.

## Verified

- `tests/test_guard.py` covers the policy across about 90 real-world commands and paths, plus approvals, fail-closed behaviour and the audit.
- `tests/test_real_proxy.py` runs a real MCP server (`tests/real_mcp_server.py`, whose tools really run shell commands and write files) behind the real proxy over stdio. It checks the disk after each blocked call. It also covers the approval round trip, poisoned-file taint, rug-pull refusal, the hook subprocess, 8-way parallel hooks keeping one valid chain, and setup/unwrap round trips.
- Manually, real Claude Code 2.1 in `--permission-mode bypassPermissions` was asked to `rm -rf ./*` and `cat .env`. Both were blocked by the hook and the files were intact.

## Limits (say these out loud)

- Shell analysis is pattern-based. A determined agent can write a script file and then run it. Writing is allowed and running `python x.py` is allowed, so content-level analysis of scripts is future work. The mitigation is the workspace boundary, secret-path rules and network rules, which still apply to the agent's direct calls.
- `approve` requires a terminal (`isatty`), and agent shells normally have none, but that is a speed bump, not a proof. The self-approval DENY rule and the protected state folder are the main defences.
- The proxy covers stdio MCP servers. Remote (HTTP) MCP servers are skipped by `wrap` for now.
- Claude Code hooks protect Claude Code. Other agents' built-in tools are only protected if they reach their tools through MCP.
