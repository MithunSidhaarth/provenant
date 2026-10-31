# What Provenant can and cannot see

Provenant does not integrate with Gmail, GitHub, Slack or any other product. It sits at the place where an agent's tool call is executed, and applies one policy engine (`agentshield/guard.py`), one approval store, one grant mechanism and one audit chain to whatever passes through that place. A product is covered when the agent reaches it through one of the boundaries below. It is not covered just because it is installed, discoverable or mentioned in a prompt.

**Observing is not preventing.** Every row says separately what Provenant sees and what it can stop. A tool call that does not pass through one of these boundaries is invisible to Provenant, and nothing in `provenant status` claims otherwise: a client counts as *connected* only after its tool traffic has appeared in the audit log.

## Capability matrix

| Boundary | How it is connected | Observes | Can block (DENY) | Can hold for a human | Inspects results | Known gaps | User configuration |
|---|---|---|---|---|---|---|---|
| **MCP proxy** (stdio) | `provenant setup` or `provenant wrap CLIENT` rewrites each local MCP server entry to launch through `provenant proxy` | every JSON-RPC message between client and server: `tools/list`, `tools/call`, `resources/read`, `prompts/get`, server-to-client requests | yes: the call is answered by the proxy and never written to the server's stdin | yes: answered with `REQUIRE_APPROVAL`, nothing forwarded; the identical call runs once after `provenant approve` | yes: results of `tools/call`, `resources/read`, `prompts/get` are scanned for injection and taint destinations | remote MCP servers (`url`/`serverUrl`, HTTP/SSE) are skipped and reported as not proxied; a client launched with its own MCP config bypasses the wrapped one; result content is passed to the agent unmodified (it taints the session, it is not rewritten) | Claude Desktop, Cursor, Windsurf, VS Code (`.vscode/mcp.json`), Claude Code project `.mcp.json`; Antigravity is experimental; restart the client |
| **Claude Code hook** | `provenant install claude-code` (or `setup`) adds PreToolUse, PostToolUse and UserPromptSubmit hooks with matcher `*` to `~/.claude/settings.json` | every Claude Code tool call (Bash, Read, Write, Edit, WebFetch, MCP tools) and every user prompt | yes: PreToolUse returns `deny`; also if the decision errors or takes over 20 s | yes, through Claude Code's own `ask` prompt (that approval is Claude Code's, not recorded by `provenant approve`) | yes: PostToolUse output taints the session; injection indicators are reported to the model | if the hook command cannot start (Python or Provenant removed), Claude Code runs the tool; not tested with Claude Code subagents or `ask` under `bypassPermissions` | none beyond install; `provenant doctor` checks the hook points at a real program |
| **Gated tool server** | `provenant serve --workspace DIR` as an MCP server (`provenant config claude-desktop` prints the entry) | every call to its own tools: read_file, list_directory, search_text, run_tests, write_file, http_get (run_command only with `--allow-shell`) | yes, before execution | yes | yes | only covers its own tools, not other servers the client also has | add the printed `mcpServers` entry |
| **Dry run** | `provenant check TOOL ARGS`, `provenant policy test` | the call you type | nothing runs | nothing runs | no | not a boundary: it shows the decision only | none |
| **Simulated world** | `python -m agentshield.server`, `python -m agentshield.demo`, `python -m agentshield.mcp_gateway` | the 8 simulated tools | yes | yes | yes | simulation only; records are labelled demo and kept out of live numbers | none |
| **Email scanning** (optional) | `provenant mail ...`; MCP email tool results through the proxy | email-shaped results; a read-only IMAP inbox with `mail watch` | the injected *send* is blocked by the normal policy; scanning itself blocks nothing | phone alerts need Bolna credentials | yes | observational; never tested with a real Gmail account or a real call from here | optional; nothing in the core needs it |

Not covered at all: agents that call APIs directly from their own code, browser automation that does not go through an MCP server, IDE features that edit files outside the agent's tool calls, a shell the human types into, and any MCP server configured somewhere Provenant has not wrapped.

## What happens at the boundary

1. The call is canonicalised (Unicode, encodings, path resolution against the workspace) and evaluated by the one Guard policy. A policy that fails to load denies everything.
2. `DENY`: the reason goes back to the agent; the tool is never invoked. The tests check this on disk, not in logs (`tests/test_real_proxy.py`).
3. `REQUIRE_APPROVAL`: stored with a fingerprint of the exact tool, arguments and session, and an expiry. Only `provenant approve` at a terminal (or a verified phone code) can release it, once.
4. `ALLOW`: a single-use grant bound to that fingerprint is issued and redeemed just before the call is forwarded.
5. Results are untrusted: destinations they mention are tainted, and injection indicators make later side effects in that session need a human.
6. Every step is appended to the hash-chained, HMAC'd audit log in `~/.provenant` with secrets redacted.

## Proxy failure behaviour

| Situation | What the proxy does |
|---|---|
| `tools/call` sent as a notification (no id) | dropped and audited; it would otherwise run with no reply |
| unknown client method | `-32601`, not forwarded |
| `params` not an object, or a non-object batch item | `-32602` / `-32600` for that message; the proxy keeps serving |
| any other error while handling one message | `-32603`, nothing forwarded |
| tool not advertised in this session, or withheld (injected description, changed definition) | `DENY`, not forwarded |
| server sends a response to an id nobody used | dropped and audited |
| server asks the client's model to generate (`sampling/createMessage`) | refused unless `PROVENANT_ALLOW_SAMPLING=1` |
| server exits mid-call | every waiting request gets an error ("outcome unknown" for allowed calls); later requests are refused with nothing sent |
| server hangs | the proxy does not time calls out; the MCP client's own request timeout applies |

## Self-protection

An agent may not run `provenant approve`, `reject`, `rollback`, `uninstall`, `unwrap`, `pins reset` or `mail disable`, and may not write to `~/.provenant` or the Claude Code settings file. These are pattern rules on shell commands and path rules on file tools: an agent that writes a script and runs it is judged on what the run command looks like (see [SECURITY_MODEL.md](SECURITY_MODEL.md#known-limits-stated-in-the-demo)).
