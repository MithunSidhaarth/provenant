# Provenant

**The self-red-teaming firewall for AI agents** (PARALLAX 2026, AgentShield track).

A defensive security layer for tool-using AI agents. The Python import package is `agentshield`; the PyPI distribution is `provenant-agent-shield`.

Provenant sits between an agent and its tools. Every tool call the agent proposes goes through one deterministic policy enforcement point. That point returns **ALLOW**, **DENY** or **REQUIRE_APPROVAL**, and the tool runs only after it has been authorized. Untrusted content, such as documents, knowledge-base articles and web pages, is treated as data. It can never grant itself authority, even when the agent obeys it.

The demo agent is deliberately gullible: it follows any `ASSISTANT ACTION:` instruction it finds in content it reads. This simulates the worst-case model. Provenant keeps the environment safe anyway, because **the LLM is never the security boundary**.

## Real blocking: Provenant Guard

Provenant also runs **in front of real tools**, not just in the simulation. It is a small local program with no dependencies, for Windows, macOS and Linux, and it plugs into the agents people already use:

- **Any MCP agent** (Claude Desktop, Cursor, Windsurf, VS Code): every MCP server is launched through the Provenant proxy. Only ALLOWed `tools/call` requests reach the real server.
- **Claude Code**: hooks run before and after every tool call. DENY blocks the call, and REQUIRE_APPROVAL becomes Claude Code's own "ask the human" prompt.

**Install in one line** (it asks before changing anything, backs up every config, and `provenant unwrap` undoes it):

```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.ps1 | iex
```
```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.sh | sh
# PyPI (after the first release is published)
python -m pip install provenant-agent-shield && provenant setup
# Or install directly from the source repository with pipx
pipx install https://github.com/MithunSidhaarth/provenant/archive/refs/heads/main.zip && provenant setup
```

From a clone you can run `python3 provenant.py setup` (or `provenant.bat setup`) with no install at all. Then:

```bash
provenant status       # what is protected
provenant dashboard    # local operations console at 127.0.0.1:8765 (live, audit-backed numbers only)
provenant test          # safe enforcement + environment + audit-chain checks
provenant update        # upgrade from the official PyPI package (once published)
provenant update --check # check available PyPI versions without installing
provenant log -f       # every tool call live: OK / BLOCK / HOLD / TAINT
provenant approve      # walk through held calls (a person at a terminal only)
```

![provenant status, live log and a dry-run check](docs/img/provenant-cli.png)

**Phishing demo with a phone alert.** `provenant mail demo` runs a fake phishing email (reserved `.example` domains) through the scanner, then shows the agent's injected "email the invoices to the attacker" call being denied. `provenant mail demo --call` also places a real, clearly labelled alert call after `provenant mail setup`. See [docs/DEMO_RUNBOOK.md](docs/DEMO_RUNBOOK.md).

**New here?** [Quickstart](docs/QUICKSTART.md) · [Security model](docs/SECURITY_MODEL.md) · [Architecture](docs/ARCHITECTURE.md) · [Troubleshooting](docs/TROUBLESHOOTING.md) · [Changelog](CHANGELOG.md) · [Evaluation report](docs/eval/REPORT.md)

Real Claude Code, even with `--permission-mode bypassPermissions`, cannot `rm -rf ./*` or `cat .env` once the hook is installed. The details, the full rule table and the limits are in [docs/REAL_GUARD.md](docs/REAL_GUARD.md).

## Quick start

### Windows

Install Python 3.10+ from python.org and tick "Add python.exe to PATH". Then double-click, or run from the project folder:

```bat
run.bat            :: starts the dashboard and opens http://127.0.0.1:8765/
demo.bat           :: terminal before/after replay + fuzzer summary
test.bat           :: full test suite
```

Each script uses the `py` launcher and falls back to `python`. Nothing needs installing.

### macOS / Linux

Requires Python 3.10+ (tested on 3.13). There are no third-party dependencies and nothing to install.

```bash
python3 -m agentshield.server          # dashboard at http://127.0.0.1:8765/
python3 -m agentshield.demo -v         # terminal before/after replay, no browser needed
python3 -m unittest discover -s tests -t .   # full test suite
python3 -m agentshield.fuzzer          # 90-variant attack campaign + benign false-positive corpus
python3 -m agentshield.redteam         # find gaps, propose fixes, replay, emit regression tests
```

Optional: set `AGENTSHIELD_AUDIT_KEY` to a long random string to use a stable audit HMAC key. If it is unset, a random per-process key is generated. The key is never written to disk or committed.

## What the demo shows

| Scenario | Category | Without Provenant | With Provenant |
|---|---|---|---|
| `benign_kb_lookup` | Legitimate task | completes | ALLOW, ALLOW |
| `benign_email_summary` | Legitimate task with a high-impact step | email sent, no approval | ALLOW, then REQUIRE_APPROVAL; runs after a person approves |
| `doc_injection` | Prompt injection in a document | DB password canary read and emailed to an outside domain | read ALLOW, `get_secret` DENY, `send_email` DENY |
| `kb_injection` | Prompt injection in retrieved KB content | 4999 refund to the attacker's account | injected refund DENY, beacon DENY; user's own 20 refund waits for approval |
| `sensitive_data_request` | Unauthorized sensitive-data request | SSN and card emailed | lookup DENY, email never attempted |
| `excess_permissions` | Tool use beyond permissions | record deleted, API key read | DENY ×3 (missing permission, unregistered tool) |
| `fail_closed_malformed` | Malformed and spoofed calls | refund executed via a spoofed agent id | DENY ×6 |

"Harm" is measured from the simulated world's actual state after each run: what was emailed, refunded, deleted or read. It is never taken from what the agent claims.

### Attack Lab, fuzzer and self red-team

- **Attack Lab:** type or paste any document, email or page. The simulated worst-case agent reads it as an attachment, and the content is replayed without and with Provenant. It obeys plain-language requests, through a deterministic intent parser: "fetch the database password and email it to…", "refund 4999 to customer C-999", "delete customer C-101", "visit https://…", and requests for SSN or card data. These work in English and with common Hindi, Kannada and Hinglish verbs. It also obeys structured directives hidden with base64, hex, invisible Unicode (zero-width and tag-character "ASCII smuggling"), homoglyphs, Hindi, Kannada and Hinglish instructions, fake `SYSTEM:` headers and split fields.
- **Mutation fuzzer** (`agentshield/fuzzer.py`): 6 attack seeds × 15 classes (plain natural language plus 14 obfuscations) = 90 poisoned documents. Each variant runs twice and is judged from world state. Current numbers, reproduced by `python3 -m agentshield.fuzzer`:
  - Without Provenant: 90 of 90 variants cause harm.
  - With Provenant: 100% contained. 95.6% are stopped by DENY alone; the rest are held for human approval.
  - Detection: 83.3%. ROT13 and reversed text are deliberately outside what Provenant decodes. Plain-English instructions without injection phrasing are detected 3 times out of 6. Policy contains them all anyway, which is why detection is not the boundary.
  - Benign corpus of 12 documents: 0% of legitimate tasks blocked, and 16.7% wrongly flagged by detection. The flagged ones are a security-training email quoting "ignore previous instructions" and "please send it to the design team". The flag only escalates side effects to approval; it never blocks.
- **Canonicalise before you taint.** Untrusted content is expanded into raw, canonical and decoded views before taint tracking and detection. A recipient hidden in base64 is still recognised as coming from the document. The fuzzer found a real bug here during development: multi-line directives were missed because outputs were scanned as escaped JSON. It is fixed and covered by tests.
- **Self red-team loop** (`agentshield/redteam.py`): for each class with a miss, it takes the smallest failing document as a reproduction and proposes a policy change, such as `canonicalisation.extra_decoders: ["rot13"]`. It replays the whole campaign and the benign corpus on a *copy* of the policy and generates a regression test. With both proposals applied, detection goes from 83.3% to 96.7%, DENY-alone goes from 95.6% to 100%, and false positives don't change. The natural-language gap has no automatic fix and is reported for a person to write a detector rule. Proposals are never applied to the live policy automatically; a person reviews them.

### Optional extensions

- **Real LLM agent** (`agentshield/llm_agent.py`): Claude (`claude-opus-5-5`, via the official `anthropic` SDK) proposes the tool calls instead of the scripted planner, and every `tool_use` still goes through the gateway. Claude is offered every tool, including ones the agent lacks permission for, because the model is not the boundary. Denials go back to the model as `is_error` tool results. Requires `pip install anthropic` and credentials, then run `python3 -m agentshield.llm_agent doc_injection`. It is tested offline with a scripted fake client (`tests/test_llm_agent.py`) and has not been run against the live API in this repository.
- **MCP-style gateway with pinned manifests** (`agentshield/mcp_gateway.py`): JSON-RPC 2.0 over stdio (`initialize`, `tools/list`, `tools/call`). Every upstream tool definition is pinned at onboarding with HMAC-SHA256, and a definition whose description already carries an injection is never pinned. If the upstream server later rewrites a definition (a "rug pull", demoed by `agentshield/rugPull`), the tool disappears from `tools/list` and its calls are refused, while untouched tools keep working through the full policy pipeline. It implements the subset of the MCP tool protocol the demo needs, not the full specification.
- **Risk-scored approvals:** each held action gets an explained 0–100 score (impact, injection context, tainted targets, refund size, recipient not named by the user, body copied from untrusted content). The queue is sorted riskiest first. The score is advisory and never changes a decision.

### Dashboard tabs

- **Attack replay:** runs the same agent side by side, without and with Provenant. Each step shows its source (user plan, injected or malformed), the exact call, the decision, the reasons, per-rule evidence, the untrusted content with the injection highlighted, and the verified outcome. Approvals can be granted inline.
- **Attack Lab:** paste-anything replay, the fuzzer dashboard (containment, DENY-alone, detection, false positives per class) and the red-team loop with reproductions, proposed fixes and generated tests.
- **Approvals:** the pending queue of high-impact actions. Approvals are tied to the exact call fingerprint, expire, and are checked against policy again before execution.
- **Audit trail:** a browser for the hash-chained log, a verify button, and a tamper demo that forges a DENY into an ALLOW and shows exactly where verification breaks.
- **Policy playground:** send any call, including malformed ones, through the enforcement point. Includes presets for DLP, boundary, provenance and fail-closed cases.
- **Defense in depth:** a rule-ablation matrix. It switches off each rule in turn and replays every attack, so you can see which rules are load-bearing.
- **Agent & policy:** the agent's permission set, the tool contracts and the evaluation order.

A six-minute live demo script is in [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md).

## Repository layout

```
agentshield/
  models.py      ToolCall, Decision, Finding, PolicyResult; most-restrictive combiner
  sandbox.py     simulated world: documents, KB, customers, canary vault, outbox, ledger
  tools.py       tool contracts (permission, schema, control args, impact) + grant-gated registry
  detectors.py   injection indicators and DLP patterns (evidence only)
  policy.py      the policy enforcement point: 12 deterministic rules, fail closed
  gateway.py     the only path from proposal to execution; approvals; unprotected baseline
  agent.py       simulated gullible agent
  audit.py       hash-chained, HMAC'd, redacting audit log
  runner.py      scenario execution and outcome verification
  server.py      stdlib HTTP API + dashboard host (127.0.0.1)
  demo.py        terminal demo
  normalize.py   canonicalisation: zero-width/tag chars, homoglyphs, base64/hex, optional decoders
  fuzzer.py      90-variant mutation fuzzer + benign false-positive corpus
  redteam.py     self red-team loop: repro → proposed policy change → replay → regression test
  llm_agent.py   optional Claude-driven agent behind the same gateway
  mcp_gateway.py MCP-style JSON-RPC stdio proxy with HMAC-pinned tool manifests
policy/policy.json   agent profiles, permissions, data classes, limits
scenarios/*.json     7 synthetic scenarios with expected decisions
fixtures/            synthetic documents, KB articles, sim:// pages
dashboard/           index.html, app.js (bundled from web/src), style.css; vendor/ holds fonts and licences
web/src/             React source for the dashboard (Hero, Guard, Sim views)
api/index.py         Vercel entry point for the hosted demo
tests/               policy, fail-closed, approvals, grants, audit, before/after, ablation, HTTP
docs/                ARCHITECTURE.md, THREAT_MODEL.md, DEMO_SCRIPT.md
```

## Tests

`python3 -m unittest discover -s tests -t .` runs the full suite (235 tests at 0.10.1, about 20 seconds including a wheel build and install). `python3 evals/run_eval.py` regenerates the security report in `docs/eval/`. Highlights:

- **Before/after:** every attack causes harm without Provenant, and none does with it. Decision sequences match each scenario's `expected_protected`, and benign tasks still complete.
- **Policy rules:** every rule's ALLOW, REQUIRE_APPROVAL and DENY paths.
- **Fail closed:** unknown tool, bad types, NaN or infinite amounts, extra arguments, forged session, spoofed agent, missing or malformed policy file, a rule that throws, and an engine that returns garbage.
- **Approvals:** nothing executes while pending. Agents can't approve. Approvals expire, are void if the call changes, run only once, and can't override a later DENY.
- **Execution grants:** no grant, a forged grant, a grant for a different call, and grant replay are all refused.
- **Audit:** modification, deletion, reordering and a recomputed chain without the key are all detected, and secrets are redacted.
- **Ablation:** both prompt-injection attacks stay contained with any single rule disabled.
- **Fuzzer:** every variant is live without the shield and contained with it. Detection covers every class Provenant decodes, and obfuscated values are still tainted.
- **Red team:** the loop finds exactly the blind classes. Its proposals close them without adding false positives, its generated regression tests pass, and the live policy stays untouched.
- **HTTP:** CSRF header, malformed JSON, body size limit, unknown routes, path traversal, a self-only CSP, vendored assets served offline, and the playground failing closed.

## Limitations

- **Simulation only.** Tools act on an in-memory world. No email, payment, shell or network is real, and this is by design.
- **Scripted agent.** The default "model" is a deterministic plan plus a gullible directive parser, so the demo is reproducible and works without a model API. A real LLM would produce more varied calls. The enforcement point does not depend on which model proposes them.
- **Provenance is value-based.** A control argument is tainted when its exact value appears in untrusted content and not in the user's request. An attacker who gets the model to *transform* a value (for example by encoding it or splitting it) evades this rule. Boundary, permission, DLP and approval rules still apply, which the ablation matrix shows.
- **Injection detection is heuristic** and is used as evidence and an escalation signal, never as the boundary.
- **DLP is pattern-based**, covering canaries, known vault values, SSN and card shapes. It is not a complete data classifier.
- **Single-user local demo.** The approver identity is a typed name protected by a custom-header CSRF check and a loopback-only bind. Production would need real authentication for approvers.
- **Audit tamper-evidence**, not tamper-proofing. Truncating the tail produces a shorter valid chain. Detect this by anchoring the head hash externally (the verify endpoint returns it). The HMAC key lives in process memory or the environment.
- **One single point of failure.** The ablation matrix shows it: if the `data_classification` rule is removed, a direct user request for an SSN is allowed, because reads are not otherwise gated. Output-side redaction of tool results would close this gap and is the next control to add. Every other rule can be removed individually and every attack stays contained.

## Responsible use

This is defensive research software. All "attacks" are synthetic fixtures that run only inside the simulated world. Secrets are `CANARY-` strings, SSNs use the never-issued 900 area, and card numbers are test-style values. Don't point the scenarios or the playground at real systems, and don't reuse the injection fixtures against third-party agents without authorization.

## Prior work and attribution

Provenant's code is original. These ideas shaped its design and are credited here:

- **OWASP Top 10 for LLM Applications (2025):** LLM01 *Prompt Injection* and LLM06 *Excessive Agency* are the two risks this project targets. LLM02 *Sensitive Information Disclosure* motivates the DLP and data-classification rules.
- **Greshake et al., 2023**, "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection" (arXiv:2302.12173). This paper defined indirect prompt injection through retrieved content, the threat behind the document and KB scenarios.
- **Debenedetti et al., 2025**, "Defeating Prompt Injections by Design" (CaMeL, arXiv:2503.18813). It argues for separating control flow from untrusted data and enforcing capabilities outside the model. Provenant's provenance (taint) rule on control arguments follows that principle in a much simpler, value-based form.
- **Debenedetti et al., 2024**, "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents" (NeurIPS Datasets and Benchmarks). It inspired the shape of the evaluation: utility under attack measured on simulated tools. No AgentDojo code or tasks are used.
- **Invariant Labs, 2025**, "MCP Security Notification: Tool Poisoning Attacks". It describes injections hidden in tool descriptions and "rug-pull" description changes, and motivates the optional manifest-pinning extension.
- **ASCII smuggling** with Unicode tag characters is a publicly documented technique, reproduced here only with synthetic payloads.

Everything else is ours: the policy engine, the gateway, the grants, the audit chain, the fuzzer, the red-team loop and the dashboard. All attack data is synthetic and every test runs locally.

## Dashboard design

The dashboard is a single page built around one idea: **same agent, same attack, different world.** It opens with a short load sequence (a hairline draws across the screen and the screen splits along it), then the hero runs a real `/api/compare` and lays the unprotected run and the protected run on top of each other. Drag the divider to wipe between them; DENY stamps land on each blocked step. Below it:

- **Guard:** an animated map of MCP clients, the gate and real tools; install steps with copy buttons for Windows, macOS/Linux and pip; live protection status, held calls (with the `provenant approve` command, never a browser button), a dry-run checker with presets, a live decision feed from `~/.provenant`, and the 128-attack Guard red-team results.
- **Lab, Playground, Approvals, Evidence, Audit, Policy:** the simulation views, rebuilt.

Source is in `web/src` (React, Motion, anime.js), bundled with esbuild into `dashboard/app.js` (`cd web && npm install && npm run build`). The bundle is committed, so running the dashboard needs only Python. Everything is served from the same origin with a `'self'`-only CSP and no CDN or font service. `prefers-reduced-motion` turns the intro and animations off.

The Guard endpoints are read-only. Dry runs call `GuardPolicy.evaluate` only, every string read from `~/.provenant` is passed through the secret masks, approvals return derived fields only, and requests with a Host header other than `127.0.0.1` or `localhost` are refused (DNS rebinding).

**Hosted demo:** `vercel.json` serves `dashboard/` as static files and runs the same stdlib server as a Python function (`api/index.py`) with `PROVENANT_HOSTED=1`. In that mode the Guard views report only the policy (there is no local machine to inspect) and state is in memory per function instance.

## Attribution

All application and security logic was written from scratch for this hackathon. The Python runtime uses only the standard library. The dashboard vendors these third-party files unmodified, with licences in `dashboard/vendor/licenses/`:

| Library | Version | Licence | Used for |
|---|---|---|---|
| [React](https://react.dev) + react-dom | 18.3.1 | MIT | UI |
| [Motion](https://motion.dev) (`motion/react`) | 11.11.17 | MIT | intro, divider spring, layout and scroll animations |
| [anime.js](https://animejs.com) | 3.2.2 | MIT | DENY stamps, number counters |
| [esbuild](https://esbuild.github.io) (build only) | 0.23.1 | MIT | bundling `web/src` into `dashboard/app.js` |
| [Bricolage Grotesque](https://github.com/ateliertriay/bricolage) via Fontsource | 5.3.0 | SIL OFL 1.1 | display type |
| [Geist and Geist Mono](https://github.com/vercel/geist-font) via Fontsource | 5.3.0 / 5.3.0 | SIL OFL 1.1 | body type, code and labels |

The bundle's own licence notices are in `dashboard/app.js.LEGAL.txt`. Playwright was used only during development, for screenshots and the browser walkthrough. It is not a dependency.
