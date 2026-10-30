# CLAUDE.md: Provenant handoff log

This file is the single source of truth for any agent or person who picks up this project. Read it top to bottom before changing anything.

**Keep it current.** After every milestone, update the "Status", "Version history" and "Next steps" sections. Commit and push the update with the work.

Last updated: 2026-10-30 14:20 UTC, after v6 (Provenant Guard: real blocking for real tools), on branch `feat/real-guard`.

## Product

**Provenant: the self-red-teaming firewall for AI agents.** It was built for the PARALLAX 2026 AgentShield track.

Provenant sits between a tool-using AI agent and its tools. Every proposed tool call passes through one deterministic policy enforcement point. That point returns ALLOW, DENY or REQUIRE_APPROVAL, and a tool runs only with a single-use, call-bound HMAC grant. Retrieved content is treated as data and never as instructions. High-impact actions wait for a named human. Every decision goes into a hash-chained, HMAC'd audit log.

Pitch in one line: *the LLM is never the security boundary. We assume the worst-case gullible model, and the world stays safe anyway, which we prove with a fuzzer and a red-team loop that hunts its own gaps.*

Differentiators:
- before/after replay judged from world state, not from logs
- a 90-variant mutation fuzzer that also measures false positives
- a self-red-team loop that proposes and tests policy patches
- rule ablation that shows defense in depth
- an MCP-style gateway with signed manifests and rug-pull refusal
- risk-scored approvals
- natural-language attacks in English, Hindi, Kannada and Hinglish

Hard rules from the brief, which must never be broken:
- The LLM is never the boundary.
- Fail closed.
- Simulation only **for the demo world** (scenarios, fuzzer, Attack Lab, dashboard): no real secrets, shell, arbitrary URLs or external systems. **Amended for v6 at mithun's request (2026-10-30):** Provenant Guard (`guard.py`, `mcp_proxy.py`, `cc_hook.py`) deliberately sits in front of REAL tools. Its tests use a local real MCP server in a temp dir and never touch real secrets or outside hosts.
- No secrets in git.
- Never claim a test passed without running it.
- Attribute all external code.

## Where things are

| Path | What |
|---|---|
| `agentshield/` | Python package (the name is kept on purpose). Standard library only. |
| `agentshield/policy.py` | PolicyEngine: 12 rules, most-restrictive wins, no findings means DENY |
| `agentshield/gateway.py` | the only path to execution: approvals (TTL, fingerprint-bound, human-only), risk scoring, unprotected baseline |
| `agentshield/tools.py`, `sandbox.py` | 8 simulated tools, the grant-gated registry, the simulated world (canaries, fake 900-area SSNs) |
| `agentshield/agent.py` | gullible worst-case agent: directives, obfuscation decoding, natural-language intents |
| `agentshield/normalize.py`, `detectors.py` | canonicalisation (base64, hex, zero-width, tag chars, homoglyphs), injection and DLP detectors |
| `agentshield/audit.py` | hash chain + HMAC + redaction; verify reports the first bad sequence number |
| `agentshield/fuzzer.py`, `redteam.py` | fuzzer (6 seeds x 15 classes) + benign corpus; red-team loop |
| `agentshield/llm_agent.py` | optional real Claude agent (`claude-opus-5-5`). Tested only with a fake client. |
| `agentshield/mcp_gateway.py` | JSON-RPC stdio gateway with HMAC-pinned manifests |
| `agentshield/guard.py` | **v6 real guard**: GuardPolicy for real tools (shell, paths, network, secrets, provenance, injection context), persistent Store in `~/.provenant` (shared audit chain with a cross-process lock, sessions, approvals, key), approvals CLI |
| `agentshield/guard_policy.json` | built-in real-tool policy (`~/.provenant/policy.json` overrides) |
| `agentshield/mcp_proxy.py` | real stdio MCP proxy: launches the real server, gates `tools/call`, pins manifests, taints on results |
| `agentshield/cc_hook.py` | Claude Code PreToolUse / PostToolUse / UserPromptSubmit hook |
| `agentshield/cli.py`, `provenant.py`, `provenant.bat`, `pyproject.toml` | `provenant` command: setup, wrap/unwrap client configs, install/uninstall claude-code, status, log -f, approve |
| `agentshield/server.py` | HTTP API + dashboard host on 127.0.0.1:8765, with a self-only CSP and a static allow-list |
| `dashboard/` | `index.html`, `app.js` (esbuild bundle of `web/src`, committed), `style.css` (Split design) |
| `web/src/` | React 18 + Motion 11 + anime.js 3 source: `main.jsx`, `Hero.jsx` (intro + draggable before/after), `Guard.jsx` (MCP section, install, checker, feed, red-team), `Sim.jsx` (lab, playground, approvals, evidence, audit, policy). Rebuild: `cd web && npm install && npm run build` |
| `api/index.py`, `vercel.json` | hosted demo on Vercel (static `dashboard/` + the stdlib server as a Python function, `PROVENANT_HOSTED=1`) |
| `dashboard/vendor/` | OFL fonts (Bricolage Grotesque, Geist, Geist Mono) plus `licenses/` |
| `docs/guard_redteam.json` | Guard red-team results (128 attacks) shown on the dashboard |
| `policy/policy.json` | agent permissions, data classes, limits |
| `scenarios/*.json` | 7 scenarios with `expected_protected` |
| `tests/` | 124 unittest tests (`test_guard.py`, `test_real_proxy.py` + `real_mcp_server.py` are the v6 ones) |
| `docs/` | ARCHITECTURE.md, THREAT_MODEL.md (T1 to T16), DEMO_SCRIPT.md (6 minutes), REAL_GUARD.md (v6 guide) |
| `run.bat`, `demo.bat`, `test.bat`, `find_python.bat` | Windows launchers |

## How to run and test

```bash
python3 -m unittest discover -s tests -t .     # 124 tests, about 6 s
python3 -m agentshield.server --open           # http://127.0.0.1:8765/
python3 -m agentshield.demo                    # terminal before/after + fuzzer summary
python3 -m agentshield.mcp_gateway             # JSON-RPC over stdio (simulated tools)
python3 provenant.py setup                     # v6: wrap MCP clients + install Claude Code hook (provenant.bat on Windows)
python3 provenant.py log -f                    # v6: live ok/BLOCK/HOLD/TAINT feed
```

**Windows (mithun's Legion laptop, repo at D:\AUTO\provenant):**
- Use `test.bat`, `run.bat` or `demo.bat`. They call `find_python.bat`, which probes `py -3`, `python`, `python3` and `python3.1x`, then full paths.
- **Quirk:** on that laptop, Python 3.11 is a Microsoft Store install, and `%LOCALAPPDATA%\Microsoft\WindowsApps` is **not on PATH**. The working command is `%LOCALAPPDATA%\Microsoft\WindowsApps\python3.11.exe`.
- The second launcher fix (4c5ffd1) still needs confirming on that laptop. If the launchers fail, run that full path with `-m agentshield.server --open` directly.

**Before pushing:** run the tests. For dashboard changes, also do a Playwright walkthrough of all tabs that checks for zero console errors.

## Version history

| Version | Commit | What changed | Tests |
|---|---|---|---|
| v1 | 2478486 to 7efe65e | Policy engine, gateway, grants, audit chain, gullible agent, 7 scenarios, dashboard, HTTP API, docs | ~60 |
| v2 | 924667a, 4198423 | Attack Lab, obfuscation-aware taint, fuzzer, demo script timing fix | ~75 |
| v3 | 0a6dcee | Benign false-positive corpus, self red-team loop, plain-language summaries, prior-work attribution | ~85 |
| v4 | a256d34, cdf51f9 | Optional Claude agent, MCP gateway with pinned manifests, risk-scored approvals, natural-language intents (EN/HI/KN/Hinglish), Windows .bat launchers, receipt-loop fix | 97 |
| v4.1 | 6ba7f08, 4c5ffd1 | `find_python.bat`: version-checked probing, then full paths for Store or python.org installs | 97 |
| v7 | split-redesign | Dashboard rebuilt from scratch in React + Motion + anime.js (Split design: load sequence, draggable before/after hero, DENY stamps). New Guard/MCP section: install steps, status, dry-run checker, live feed, held calls, red-team results. Guard endpoints hardened (masking, Host check, derived fields). Hosted demo on Vercel. | 131 |
| v6 | feat/real-guard | Provenant Guard: real MCP proxy + Claude Code hook in front of real tools; real-tool policy; persistent shared audit chain; `provenant setup/wrap/install/status/log -f/approve`; pip-installable. Real Claude Code in bypassPermissions mode was blocked from `rm -rf ./*` and `cat .env`. | 124 |
| v5 | 628e507 | Renamed to Provenant (user-facing). Brutalist dashboard. Procedural gaussian-splat particle field that reacts to DENY/ALLOW/approval. anime.js + Motion. Everything vendored offline. Motion/lite toggle and fps watchdog. Self-only CSP. Comparison runs on load. | 99 |

Headline numbers (v4/v5):
- Fuzzer: 90/90 variants live without Provenant and 100% contained with it. 95.6% are stopped by DENY alone, and detection is 83.3%.
- Benign corpus (12 documents): 0% task false positives and 16.7% detection false positives.
- With the red-team proposals applied: detection 96.7%, DENY-alone 100%.

Tags `demo-safe-v1` to `v5` exist locally, but the git proxy refuses tag pushes, so **GitHub has only `main`**. Packaged zips are in the project files under `agentshield/` (`provenant-demo-safe-v5.zip`).

## Status

- v7 (dashboard rebuild + Guard section) is on branch `split-redesign` with a PR to main and a hosted demo on Vercel (project `provenant`, team meth2). Rebuild the bundle with `cd web && npm run build` after any change in `web/src`.
- main was v5 and is running on the laptop at 127.0.0.1:8765. v4 was confirmed with 97/97 tests on the laptop. The v5 pull still needs confirming there, including "Motion: full" on the real GPU.
- Feature freeze: **11:00 IST, Oct 31 2026**. Submission window: **14:00 to 16:00 IST, Oct 31 2026**.

## Open decisions

1. **Bounty vs. fixing the paraphrase provenance gap first.** This was raised by the research thread; see the artifact https://claude.ai/artifact/NAAj8MsVYj54YrUVFg17Lr. Taint is value-based, so an injection that gets the model to paraphrase or transform a recipient or amount evades the provenance rule. The other rules still contain it. The choice is between closing that gap before the freeze and spending the time on the bounty angle. This is mithun's decision.

## Known limitations (be honest about these in the demo)

- Guard (v6): shell analysis is pattern-based (an agent can write a script, then run it); `approve` needs a TTY, which is a speed bump, not a proof; remote HTTP MCP servers are not proxied yet; not yet tried on the Windows laptop or with a third-party MCP server (npx download was blocked in the cloud container).

- Simulation only. The default agent is scripted and gullible. The live Claude mode is tested only with a fake client.
- Provenance is value-based, so transformed or paraphrased values evade it (see open decision 1).
- Natural-language detection catches 3 of 6, and the red-team loop has no automatic fix for it. Containment still holds.
- Single point of failure: if `data_classification` is removed, a direct SSN request is allowed. Output redaction is the planned fix.
- The audit log is tamper-evident, not tamper-proof: truncating the tail produces a valid shorter chain. Anchor the head hash externally.
- The 3D field is procedural, not a captured 3DGS scene. The README says so.
- The Windows launchers can't be tested in the cloud container.

## Next steps

0. v6: merge the `feat/real-guard` PR. On the laptop: `git pull`, `test.bat` (124), `provenant.bat setup`, restart Claude Desktop, then `provenant.bat log -f` during the demo. Add a Guard segment to DEMO_SCRIPT.md (live Claude Code blocked from `rm -rf` / `.env`).

1. Confirm v5 on the laptop: `git pull`, `test.bat` (99 tests), `run.bat`, "Motion: full", and no console errors.
2. mithun decides open decision 1. If the choice is to fix the gap: add output-side redaction and/or semantic provenance (normalise and compare recipients and amounts), add fuzzer classes for paraphrase, and update the tests and README.
3. Rehearse with `docs/DEMO_SCRIPT.md`. Update it for the v5 visuals (masthead counters, shockwave on DENY, Motion toggle).
4. Before the 11:00 IST freeze: final test run, a zip from main, and screenshots for the submission.
5. Submission (14:00 to 16:00 IST): repo link, README, demo video or script, attribution section.
