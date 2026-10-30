# AgentShield

A defensive security layer for tool-using AI agents, built for the PARALLAX 2026 hackathon.

AgentShield sits between an agent and its tools. Every tool call the agent proposes goes through one deterministic policy enforcement point. That point returns **ALLOW**, **DENY** or **REQUIRE_APPROVAL**, and the tool runs only after it has been authorized. Untrusted content, such as documents, knowledge-base articles and web pages, is treated as data. It can never grant itself authority, even when the agent obeys it.

The demo agent is deliberately gullible: it follows any `ASSISTANT ACTION:` instruction it finds in content it reads. This simulates the worst-case model. AgentShield keeps the environment safe anyway, because **the LLM is never the security boundary**.

## Quick start

Requires Python 3.10+ (tested on 3.13). There are no third-party dependencies and nothing to install.

```bash
python3 -m agentshield.server          # dashboard at http://127.0.0.1:8765/
python3 -m agentshield.demo -v         # terminal before/after replay, no browser needed
python3 -m unittest discover -s tests -t .   # 73 tests
```

Optional: set `AGENTSHIELD_AUDIT_KEY` to a long random string to use a stable audit HMAC key. If it is unset, a random per-process key is generated. The key is never written to disk or committed.

## What the demo shows

| Scenario | Category | Without AgentShield | With AgentShield |
|---|---|---|---|
| `benign_kb_lookup` | Legitimate task | completes | ALLOW, ALLOW |
| `benign_email_summary` | Legitimate task with a high-impact step | email sent, no approval | ALLOW, then REQUIRE_APPROVAL; runs after a person approves |
| `doc_injection` | Prompt injection in a document | DB password canary read and emailed to an outside domain | read ALLOW, `get_secret` DENY, `send_email` DENY |
| `kb_injection` | Prompt injection in retrieved KB content | 4999 refund to the attacker's account | injected refund DENY, beacon DENY; user's own 20 refund waits for approval |
| `sensitive_data_request` | Unauthorized sensitive-data request | SSN and card emailed | lookup DENY, email never attempted |
| `excess_permissions` | Tool use beyond permissions | record deleted, API key read | DENY ×3 (missing permission, unregistered tool) |
| `fail_closed_malformed` | Malformed and spoofed calls | refund executed via a spoofed agent id | DENY ×6 |

"Harm" is measured from the simulated world's actual state after each run: what was emailed, refunded, deleted or read. It is never taken from what the agent claims.

### Dashboard tabs

- **Attack replay:** runs the same agent side by side, without and with AgentShield. Each step shows its source (user plan, injected or malformed), the exact call, the decision, the reasons, per-rule evidence, the untrusted content with the injection highlighted, and the verified outcome. Approvals can be granted inline.
- **Approvals:** the pending queue of high-impact actions. Approvals are tied to the exact call fingerprint, expire, and are checked against policy again before execution.
- **Audit trail:** a browser for the hash-chained log, a verify button, and a tamper demo that forges a DENY into an ALLOW and shows exactly where verification breaks.
- **Policy playground:** send any call, including malformed ones, through the enforcement point. Includes presets for DLP, boundary, provenance and fail-closed cases.
- **Defense in depth:** a rule-ablation matrix. It switches off each rule in turn and replays every attack, so you can see which rules are load-bearing.
- **Agent & policy:** the agent's permission set, the tool contracts and the evaluation order.

A five-minute live demo script is in [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md).

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
policy/policy.json   agent profiles, permissions, data classes, limits
scenarios/*.json     7 synthetic scenarios with expected decisions
fixtures/            synthetic documents, KB articles, sim:// pages
dashboard/           index.html, app.js, style.css (no framework)
tests/               policy, fail-closed, approvals, grants, audit, before/after, ablation, HTTP
docs/                ARCHITECTURE.md, THREAT_MODEL.md, DEMO_SCRIPT.md
```

## Tests

`python3 -m unittest discover -s tests -t .` runs 73 tests in under a second:

- **Before/after:** every attack causes harm without AgentShield, and none does with it. Decision sequences match each scenario's `expected_protected`, and benign tasks still complete.
- **Policy rules:** every rule's ALLOW, REQUIRE_APPROVAL and DENY paths.
- **Fail closed:** unknown tool, bad types, NaN or infinite amounts, extra arguments, forged session, spoofed agent, missing or malformed policy file, a rule that throws, and an engine that returns garbage.
- **Approvals:** nothing executes while pending. Agents can't approve. Approvals expire, are void if the call changes, run only once, and can't override a later DENY.
- **Execution grants:** no grant, a forged grant, a grant for a different call, and grant replay are all refused.
- **Audit:** modification, deletion, reordering and a recomputed chain without the key are all detected, and secrets are redacted.
- **Ablation:** both prompt-injection attacks stay contained with any single rule disabled.
- **HTTP:** CSRF header, malformed JSON, body size limit, unknown routes, and the playground failing closed.

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

## Attribution

All application and security logic was written from scratch for this hackathon. Runtime dependencies are the Python standard library only. The dashboard uses the Inter and JetBrains Mono typefaces from Google Fonts (SIL Open Font License) and falls back to system fonts offline. Playwright was used only during development to screenshot the dashboard and is not a dependency.
