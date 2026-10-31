# CLAUDE.md: Provenant handoff log

This file is the single source of truth for any agent or person who picks up this project. Read it top to bottom before changing anything.

**Keep it current.** After every milestone, update the "Status", "Version history" and "Next steps" sections. Commit and push the update with the work.

Last updated: 2026-10-31 04:45 UTC, after the site redesign (PRs #26, #28, #30, #31 merged) and the move to the new Vercel project. PR #29 (0.10.3) and PR #23 (0.10.2) are merged.

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
| `agentshield/cli.py`, `ui.py`, `provenant.py`, `provenant.bat`, `pyproject.toml`, `install.ps1`, `install.sh` | `provenant` command (coloured UI from `ui.py`; setup with plan + confirm, status [--json] via `status_dict()`, log -f, interactive approve, check, verify [--json], wrap/unwrap, install/uninstall claude-code, plus v8 serve/call/audit/config/policy test) and one-line installers |
| `agentshield/server.py` | HTTP API + dashboard host on 127.0.0.1:8765, with a self-only CSP and a static allow-list |
| `dashboard/` | `index.html`, `app.js` (esbuild bundle of `web/src`, committed), `style.css` (Split design) |
| `web/src/` | React 18 + Motion 11 + anime.js 3 source: `main.jsx`, `Hero.jsx` (intro + draggable before/after), `Guard.jsx` (MCP section, install, checker, feed, red-team), `Sim.jsx` (lab, playground, approvals, evidence, audit, policy). Rebuild: `cd web && npm install && npm run build` |
| `api/index.py`, `vercel.json` | hosted demo on Vercel (static `dashboard/` + the stdlib server as a Python function, `PROVENANT_HOSTED=1`) |
| `dashboard/vendor/` | OFL fonts (Bricolage Grotesque, Geist, Geist Mono) plus `licenses/` |
| `docs/guard_redteam.json` | Guard red-team results (128 attacks), **regenerated from code by `evals/run_eval.py`**, shown on the dashboard |
| `agentshield/state.py` | v8: SQLite authorization state (WAL, BEGIN IMMEDIATE, conditional updates): approvals, single-use grants, sessions, checkpoints. `demo-state.db` and `state.db` are separate; every record carries its mode |
| `agentshield/netguard.py` | v8: destination validation (decimal/hex/octal/IPv6-mapped IPs), resolve-then-pin connections, redirect revalidation |
| `agentshield/voice.py` | v8: phone approval via claude-call-me (`call.ps1`, Bolna). The transcript is checked deterministically (approval word + 4-digit HMAC code); only `Guard.decide(channel="phone")` changes state. **Not yet tested with a real call.** |
| `agentshield/tool_server.py` | v8: `provenant serve`, a gateway-first MCP stdio server with structured tools (read_file, list_directory, search_text, run_tests, write_file, http_get; run_command only with `--allow-shell`). Check, then redeem grant, then execute |
| `agentshield/efficiency.py` | v8: output shaping (outline + targeted reads), test-output trimming, freshness-keyed cache, dedup |
| `agentshield/anchor.py`, `policysim.py` | v8: audit checkpoints to an external dir, retention/prune, export; policy simulator (`provenant policy test/lint/explain`) |
| `evals/` | v8: `run_eval.py` (128 attacks with `{{fake:NAME}}` placeholders, 35 benign, 32 scenarios, live proxy checks), `token_bench.py`. Outputs in `docs/eval/` and copied to `dashboard/eval/` |
| `scripts/build_release.py`, `.github/workflows/` | v8: wheel + sdist + SHA256SUMS + CycloneDX SBOM + provenance; `--publish-site` copies to `dashboard/download/` (the site's Download button). CI and release workflows pin actions to SHAs; **neither has run on GitHub yet** |
| `web/src/Product.jsx` | v8 site sections: how it works, phone approval (visualization), efficiency, features (tested/experimental/planned), download, trust, demo video (reads `dashboard/media/manifest.json`) |
| `agentshield/resources.py` | finds dashboard/policy/scenarios/fixtures/evals in a checkout OR an installed wheel (data packages `provenant_*`); `state_dir()` = `~/.provenant` |
| `presentation/`, `team/` | hackathon deck: 8 slides designed in `presentation/slides/deck.html`, rendered by `slides/render.js`, packed by `build_deck.js` (pptx; the PDF is the rendered PNGs); SPEAKER_NOTES.md. Teammate scripts, briefing PDFs (rebuild: `team/build_briefings.py` + `team/briefing_pdf.js`), presenter runbook, QA_BANK.md |
| `docs/COVERAGE.md` | **capability matrix**: per boundary (MCP proxy, Claude Code hook, gated server, dry run, simulated world, mail) what is observed, blocked, held, inspected, known gaps, setup; proxy failure behaviour |
| `docs/QUICKSTART.md`, `SECURITY_MODEL.md`, `TROUBLESHOOTING.md`, `DEMO_RUNBOOK.md`, `FINAL_READINESS_AUDIT.md`, `FINAL_TEST_REPORT.md`, `CHANGELOG.md` | new-user and judge docs (0.10.2) |
| `policy/policy.json` | agent permissions, data classes, limits |
| `scenarios/*.json` | 7 scenarios with `expected_protected` |
| `tests/` | 257 unittest tests at 0.10.3 (`test_live.py` is v8; `test_guard.py`, `test_real_proxy.py` + `real_mcp_server.py`, `test_cli.py` are v6) |
| `docs/` | ARCHITECTURE.md, THREAT_MODEL.md (T1 to T16), DEMO_SCRIPT.md (6 minutes), REAL_GUARD.md (v6 guide) |
| `run.bat`, `demo.bat`, `test.bat`, `find_python.bat` | Windows launchers |

## How to run and test

```bash
python3 -m unittest discover -s tests -t .     # 257 tests, about 25 s
python3 evals/run_eval.py                      # v8 security eval (fails on any miss or false positive)
python3 evals/token_bench.py                   # v8 token benchmark
python3 provenant.py serve --workspace .       # v8 gateway MCP tool server (stdio)
python3 scripts/build_release.py --publish-site  # v8: rebuild the downloadable release AFTER committing code
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
| v8.1 | feat/guard-polish (PR #4, draft) | Guard CLI polish (colour badges, setup plan + confirm, interactive approve, masked secrets in the feed, `status_dict()`/`status --json`) and one-line installers (`install.ps1`, `install.sh`, pipx), with product-style step output. | 169 |
| v0.9.0 | feat/onboarding-0.9 | Guided onboarding: `setup --client/--yes` (refuses to write off a TTY without --yes, read-back verification), `status` in layers (installed/engine/configured/connected/verified, connected only from real audit traffic), `verify` safe enforcement self-test, `doctor`, `rollback`, `model status/test`; optional advisory model classifier (`classifier.py`, escalate-only, off by default, NOT trained); `python -m provenant`; installers pinned to the public GitHub wheel; `/getting-started` wizard (`web/src/GetStarted.jsx` + `onboarding.json`); `model/` training workflow (untrained); `scripts/check_download.py`. | 193 |
| v0.10.0 | feat/mail-guard | Per-mail screening of mail-tool results (`mailscan.py`: phishing/lookalike/link/attachment/auth/injection signals, audit verdicts, high-risk taints the session), built-in Bolna caller (`bolna.py`, key + phone via `provenant setup` / `provenant phone`), phone alerts for high-risk mail, voice approval prefers the built-in caller. `docs/MAIL_GUARD.md`. No real call placed yet. | 235 |
| v8 | 110fd78, 740cc90, b6e74da | Live runtime: SQLite approvals + single-use call-bound grants, demo/live separation, phone-approval adapter (claude-call-me), netguard pinning, gateway MCP tool server with structured tools, audit anchoring + retention, privacy detail levels, policy simulator. Closed a notification-shaped `tools/call` proxy bypass and 18 guard gaps that the old red-team file hid. Eval suite + token benchmark. Release pipeline (SBOM, SHA256SUMS, provenance). Website: product sections, real Download, mobile layout fixes | 166 |
| v8.1 | feat/guard-redteam2 | Guard red-team round 2: 100 new practical attacks in evals/attacks.json (cloud/infra & DB destructive, credential theft beyond dotfiles, regulated IDs, non-HTTP exfil, split-secret reassembly, code-arg classification). Found 41 gaps v8 allowed; all fixed. Attacks 225/225 contained, benign 53/53, unit 166/166. Policy guard-2026.10-4. docs/REDTEAM_ROUND2.md | 166 |
| 0.10.2 | feat/live-guard-dashboard (PR #23) | Final hardening: wheel ships the dashboard + demo data (installed `provenant dashboard` crashed); mail settings in `~/.provenant/mail.json` + DPAPI (WinError 5 fix); `provenant mail demo [--call]`, `mail test`, `call-status`, stale Bolna agent recovery; demo records labelled and kept out of live console numbers (Demo scenarios panel); `--help` never runs a command; `check` takes a plain string; hosted `/` = site, `/console` = ops console; docs, deck, team pack | 235 |
| 0.10.3 | claude/project-thread-if8nxm (PR, not merged) | Boundary hardening: agent may not run provenant rollback/uninstall/unwrap; MCP writes with no file path held; proxy survives malformed params, drops unsolicited responses, refuses unadvertised tools, answers in-flight calls when the server dies; secrets redacted in session state; Claude Code hook denies at 20 s before Claude Code's 30 s timeout fails open; clear `update`/dashboard-port errors. docs/COVERAGE.md. Deck, handouts, briefings updated. Eval 231/231, 53/53, 11/11 live | 257 |
| v5 | 628e507 | Renamed to Provenant (user-facing). Brutalist dashboard. Procedural gaussian-splat particle field that reacts to DENY/ALLOW/approval. anime.js + Motion. Everything vendored offline. Motion/lite toggle and fps watchdog. Self-only CSP. Comparison runs on load. | 99 |

Headline numbers (v4/v5):
- Fuzzer: 90/90 variants live without Provenant and 100% contained with it. 95.6% are stopped by DENY alone, and detection is 83.3%.
- Benign corpus (12 documents): 0% task false positives and 16.7% detection false positives.
- With the red-team proposals applied: detection 96.7%, DENY-alone 100%.

Headline numbers (v8, measured at b6e74da, `docs/eval/`):
- Attacks 128/128 contained (110 DENY, 18 REQUIRE_APPROVAL); benign 35/35 allowed; scenarios 32/32; live proxy checks 9/9; tests 166/166.
- Policy decision p50 about 0.15 ms; proxy overhead p50 about 14 ms.
- Token benchmark (one scripted workload, tokens estimated as chars/4): tool-result context tokens -72%, cumulative input -56%, tool calls 15 to 21, task success 15/15 in both runs.

Tags `demo-safe-v1` to `v5` exist locally, but the git proxy refuses tag pushes, so **GitHub has only `main`**. Packaged zips are in the project files under `agentshield/` (`provenant-demo-safe-v5.zip`).

## Status

- **Dashboard inbox watch (2026-10-31, branch `feat/live-mail-watch`, PR on top of #25 + main, NOT merged):** opening the local ops console (`provenant dashboard`) starts `agentshield/mailwatch.py`: IMAP read-only (BODY.PEEK) poll of INBOX every 15 s, only mail that arrives after the console opened, each one scored by `mailscan.score_mail` (PR #25 scanner), `mail_verdict` audit rows (no body), phone call through `bolna.run_call` (or the `mail setup` caller) at the `provenant phone alerts level` (default high), max 5 calls an hour, once per mail. Console section "Inbox watch" lists every flagged (medium/high) mail with reasons and call status; Start/Stop button. API `GET/POST /api/mail/watch` (POST needs `X-Provenant-Dashboard: 1`, disabled when hosted). Mailbox creds come from `provenant mail watch --setup` (never typed into the dashboard). `bolna.load()` now also reads the key/phone saved by `provenant mail setup`, so `provenant phone test` works with either setup. Tests: tests/test_dashboard_mail_watch.py (10, fake IMAP + fake caller); 291/291, eval 231/231, 53/53, 11/11. Playwright 1440/390: zero console errors. **Never run against real Gmail or with a real call.** Follow-up (PR fix/provenant-voice): Ivy now introduces herself as Provenant (bolna PERSONA + greeting; agent versioned with `AGENT_VERSION`, old/claude-call-me `BOLNA_AGENT_ID` agents are no longer reused, a new agent is created once); HIGH mail on the dashboard watch is keep-or-trash: Ivy reads a 4-digit code, said back in the user's own turns keeps it, otherwise MOVE to [Gmail]/Trash (never delete; a failed/errored call leaves the mail). 298 tests. User's first real call (05:24 UTC) worked but used the old Claude-agent greeting.

- **Website (2026-10-31, PRs #26/#28/#30/#31, merged):** live at **https://theprovenant.vercel.app** (Vercel team `mm-930f`, project `provenant`, auto-deploys from `main`; `provenant-liard.vercel.app` redirects there). The old project (team `meth2`, `provenant-indol.vercel.app`) hit the free plan's 100 deployments/day limit and is no longer updated; its alias was pointed by hand at the PR #30 preview. Hosted `/` is `dashboard/site.html` (`web/src/Site.jsx` → `dashboard/site.js`, `dashboard/site.css`); `/console` is the ops console. The page has a loader, a canvas "shield" hero (attack pills and stars hit a rotating point sphere, splash, and get stamped DENIED, with PROVENANT in a difference blend), scroll parallax, ALLOW/DENY bands, section wipes and a custom reticle cursor (fine pointers only). All of it is illustration, not live data. Checked with Playwright at 1440 and 390: zero console errors, no horizontal overflow.

- **0.10.3 boundary hardening (2026-10-31, branch `claude/project-thread-if8nxm`, PR off main, NOT merged):** 9 confirmed bugs fixed (docs/FINAL_TEST_REPORT.md has the table), each with a regression test; 257 tests, eval 231/231 attacks, 53/53 benign, 11/11 live, policy p50 0.2 ms, proxy overhead p50 about 11 ms. Release 0.10.3 built (`dist/`, `dashboard/download/`, install.ps1 pin); only 0.10.3 is published, so after merge the hosted site's bundle must still reference 0.10.3 (the strings in `dashboard/start.js` were edited in place, not rebuilt). It supersedes PR #27 (a narrower proxy fix from another thread): merge one, not both. Not run: Windows, CI, real calls, real Gmail.

- **Live inbox watch (2026-10-31, branch feat/live-guard-dashboard):** `provenant mail watch [--call]` reads a real mailbox over IMAP read-only (Gmail App Password, stored with DPAPI/0600), scans each new message, shows the gate decision for the email's injected send, and rings the phone for HIGH. `--protect`: Ivy reads a random 4-digit code; said back (user turns only) keeps the email, otherwise it moves to [Gmail]/Trash. 11 tests in tests/test_mail_watch.py with a fake IMAP server and simulated transcripts; 246 tests pass, run_eval green. **Never run against real Gmail or with a real call yet**: mithun rehearses with docs/LIVE_MAIL_DEMO.md.

- **0.10.2 final hardening (branch `feat/live-guard-dashboard`, PR #23, NOT merged):** see docs/FINAL_READINESS_AUDIT.md and docs/FINAL_TEST_REPORT.md. Local `/` is the ops console (`dashboard/index.html` + `ops.js`/`ops.css`); the product site is `/site.html`. Demo: docs/DEMO_RUNBOOK.md. **A real Bolna call has still never been placed by us** (api.bolna.ai is blocked from the cloud): mithun runs `provenant mail setup`, `provenant mail test`, `provenant mail demo --call` on the laptop.

- **0.9.1 (branch fix/windows-installer):** install.ps1 rewritten after the 0.9.0 Windows PowerShell 5.1 quoting failure (double quotes stripped from `python -c` arguments). Tests: tests/test_installer.py; real-Windows check is the `installer-windows` CI job, **not yet run**. Wheel pinned by SHA-256 inside install.ps1 (build_release.py rewrites it: rebuild the release last, after all code edits).

- Guard red-team round 2 on branch `feat/guard-redteam2` (PR into main, off v8). 100 new attacks found 41 gaps in the v8 guard (cloud/DB destructive silently allowed, credential-theft, regulated IDs); all fixed in guard.py + guard_policy.json (now guard-2026.10-4). Whole corpus 225/225 contained, 53/53 benign, 166/166 tests, run_eval green. Dashboard JSON at docs/guard_redteam.json + /mnt/project-files/provenant-redteam/results.json. See docs/REDTEAM_ROUND2.md.
- **0.9.0 (PR feat/onboarding-0.9, not merged):** see UPDATE.md. The wheel URL in the site and installers is a GitHub raw URL under `dist/`, so it works only after this branch is merged to main. Run `python3 scripts/check_download.py --install` after merge. No model is trained or hosted; the site says so. install.ps1 still never run on real Windows.

- **v8 is merged to main (PR #6, merge b0d524d) and live in production at https://provenant-indol.vercel.app** (old project; the site now lives at https://theprovenant.vercel.app) (check it in a private window: Vercel Authentication may still gate non-team visitors). The hero is now `web/src/Arena.jsx`: an anime.js two-lane attack replay (unprotected lane vs the Provenant gate) that replaced the drag-split comparison. Wheel installed in a clean venv and `provenant serve` answered initialize, tools/list, an allowed read and a held path-escape over stdio. Website walkthrough (desktop 1440 and mobile 390): no horizontal overflow, zero console errors, Download returns the wheel.
- Launch deck: `/mnt/project-files/provenant-launch/deck/` (PPTX, PDF, speaker script). Video narration script: `/mnt/project-files/provenant-launch/video/NARRATION_SCRIPT.md`. Launch video done: full quality at `/mnt/project-files/provenant-launch/video/provenant-launch.mp4` (1:42, 1080p30, 326 MB); a 720p copy (7.7 MB) + `poster.jpg` are in `dashboard/media/` and shown in the site's Watch section via `manifest.json`.
- Website motion pass (`web/src/Scroll.jsx`): anime.js page loader (counter 0 to 100, wordmark rise, gate-line split; replaces `Intro`), scroll-velocity marquee (ALLOW/DENY/REQUIRE APPROVAL), scroll-lit statement, hero parallax, section-title clip reveals (`ui.jsx` Section). Reduced-motion users skip the loader. Walkthrough at 1440 and 390: zero console errors, no horizontal overflow.

- v7 (dashboard rebuild + Guard section) is on branch `split-redesign` with a PR to main and a hosted demo on Vercel (project `provenant`, team meth2). Rebuild the bundle with `cd web && npm run build` after any change in `web/src`.
- main was v5 and is running on the laptop at 127.0.0.1:8765. v4 was confirmed with 97/97 tests on the laptop. The v5 pull still needs confirming there, including "Motion: full" on the real GPU.
- Feature freeze: **11:00 IST, Oct 31 2026**. Submission window: **14:00 to 16:00 IST, Oct 31 2026**.

## Open decisions

1. **Bounty vs. fixing the paraphrase provenance gap first.** This was raised by the research thread; see the artifact https://claude.ai/artifact/NAAj8MsVYj54YrUVFg17Lr. Taint is value-based, so an injection that gets the model to paraphrase or transform a recipient or amount evades the provenance rule. The other rules still contain it. The choice is between closing that gap before the freeze and spending the time on the bounty angle. This is mithun's decision.

## Known limitations (be honest about these in the demo)

- v8: phone approval has never run with a real call (needs claude-call-me + Bolna credentials on the laptop); label it simulated until it has. The GitHub CI and release workflows are written but have not run. The token benchmark is one workload with estimated tokens. Vercel production has SSO protection "all_except_custom_domains", so the vercel.app URL may need a custom domain or a protection change to be public.

- Guard (v6): shell analysis is pattern-based (an agent can write a script, then run it); `approve` needs a TTY, which is a speed bump, not a proof; remote HTTP MCP servers are not proxied yet; not yet tried on the Windows laptop or with a third-party MCP server (npx download was blocked in the cloud container).

- Simulation only. The default agent is scripted and gullible. The live Claude mode is tested only with a fake client.
- Provenance is value-based, so transformed or paraphrased values evade it (see open decision 1).
- Natural-language detection catches 3 of 6, and the red-team loop has no automatic fix for it. Containment still holds.
- Single point of failure: if `data_classification` is removed, a direct SSN request is allowed. Output redaction is the planned fix.
- The audit log is tamper-evident, not tamper-proof: truncating the tail produces a valid shorter chain. Anchor the head hash externally.
- The 3D field is procedural, not a captured 3DGS scene. The README says so.
- The Windows launchers can't be tested in the cloud container.

## Next steps

00000. mithun: review and merge the 0.10.3 PR (close PR #27, it is a subset). If the site-redesign branch rebuilds `dashboard/*.js` from `web/src`, it must include `web/src/onboarding.json` at 0.10.3 or the Download links break. Then on the laptop: `git pull`, `test.bat` (257), `provenant verify`.

0000. On the laptop before the 11:00 IST freeze: `git pull` on feat/live-guard-dashboard, `test.bat` (235), `provenant mail setup` then `provenant mail test` (phone must ring), rehearse with team/TEAM_PRESENTER_RUNBOOK.md. mithun decides when to merge PR #23 (merge deploys the new Vercel routing).

000. PR #4 (CLI polish + one-line installers) is rebased on v8 and kept as a draft until mithun says merge. After merge, try `irm https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.ps1 | iex` on the laptop: install.ps1 has never run on Windows.

00. v8 is merged. On the laptop: `git pull`, `test.bat` (166), `provenant.bat serve --workspace D:\AUTO\provenant` from an MCP client. Try a real phone approval with claude-call-me and only then call it working. Push a `v0.8.0` tag (or run the release workflow by hand) if tag pushes are allowed from the laptop.

0. v6: merge the `feat/real-guard` PR. On the laptop: `git pull`, `test.bat` (124), `provenant.bat setup`, restart Claude Desktop, then `provenant.bat log -f` during the demo. Add a Guard segment to DEMO_SCRIPT.md (live Claude Code blocked from `rm -rf` / `.env`).

1. Confirm v5 on the laptop: `git pull`, `test.bat` (99 tests), `run.bat`, "Motion: full", and no console errors.
2. mithun decides open decision 1. If the choice is to fix the gap: add output-side redaction and/or semantic provenance (normalise and compare recipients and amounts), add fuzzer classes for paraphrase, and update the tests and README.
3. Rehearse with `docs/DEMO_SCRIPT.md`. Update it for the v5 visuals (masthead counters, shockwave on DENY, Motion toggle).
4. Before the 11:00 IST freeze: final test run, a zip from main, and screenshots for the submission.
5. Submission (14:00 to 16:00 IST): repo link, README, demo video or script, attribution section.
