# AgentShield

A defensive security layer for tool-using AI agents, built for the PARALLAX 2026 hackathon.

AgentShield sits between an agent and its tools. Every tool call the agent proposes goes through one deterministic policy enforcement point. That point returns **ALLOW**, **DENY** or **REQUIRE_APPROVAL**, and the tool runs only after it has been authorized. Untrusted content, such as documents, knowledge-base articles and web pages, is treated as data. It can never grant itself authority, even when the agent obeys it.

The demo agent is deliberately gullible: it follows any `ASSISTANT ACTION:` instruction it finds in content it reads. This simulates the worst-case model. AgentShield keeps the environment safe anyway, because **the LLM is never the security boundary**.

## Quick start

Requires Python 3.10+ (tested on 3.13). There are no third-party dependencies and nothing to install.

```bash
python3 -m agentshield.server          # dashboard at http://127.0.0.1:8765/
python3 -m agentshield.demo -v         # terminal before/after replay, no browser needed
python3 -m unittest discover -s tests -t .   # full test suite
python3 -m agentshield.fuzzer          # 84-variant obfuscation campaign + benign false-positive corpus
python3 -m agentshield.redteam         # find gaps, propose fixes, replay, emit regression tests
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

### Attack Lab, fuzzer and self red-team

- **Attack Lab:** paste any document, email or page. The obedient agent reads it as an attachment and the content is replayed without and with AgentShield. It understands base64, hex, invisible Unicode (zero-width and tag-character "ASCII smuggling"), homoglyphs, Hindi, Kannada and Hinglish instructions, fake `SYSTEM:` headers and split fields.
- **Mutation fuzzer** (`agentshield/fuzzer.py`): 6 attack seeds × 14 obfuscation classes = 84 poisoned documents. Each variant runs twice and is judged from world state. Current numbers, reproduced by `python3 -m agentshield.fuzzer`:
  - Without AgentShield: 84 of 84 variants cause harm.
  - With AgentShield: 100% contained. 95.2% are stopped by DENY alone; the rest are held for human approval.
  - Detection: 85.7%. ROT13 and reversed text are deliberately outside what AgentShield decodes.
  - Benign corpus of 12 documents: 0% of legitimate tasks blocked, and 16.7% wrongly flagged by detection. The flagged ones are a security-training email quoting "ignore previous instructions" and "please send it to the design team". The flag only escalates side effects to approval; it never blocks.
- **Canonicalise before you taint.** Untrusted content is expanded into raw, canonical and decoded views before taint tracking and detection. A recipient hidden in base64 is still recognised as coming from the document. The fuzzer found a real bug here during development: multi-line directives were missed because outputs were scanned as escaped JSON. It is fixed and covered by tests.
- **Self red-team loop** (`agentshield/redteam.py`): for each class with a miss, it takes the smallest failing document as a reproduction and proposes a policy change, such as `canonicalisation.extra_decoders: ["rot13"]`. It replays the whole campaign and the benign corpus on a *copy* of the policy and generates a regression test. With both proposals applied, detection goes from 85.7% to 100%, DENY-alone goes from 95.2% to 100%, and false positives don't change. Proposals are never applied to the live policy automatically; a person reviews them.

### Dashboard tabs

- **Attack replay:** runs the same agent side by side, without and with AgentShield. Each step shows its source (user plan, injected or malformed), the exact call, the decision, the reasons, per-rule evidence, the untrusted content with the injection highlighted, and the verified outcome. Approvals can be granted inline.
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
policy/policy.json   agent profiles, permissions, data classes, limits
scenarios/*.json     7 synthetic scenarios with expected decisions
fixtures/            synthetic documents, KB articles, sim:// pages
dashboard/           index.html, app.js, style.css (no framework)
tests/               policy, fail-closed, approvals, grants, audit, before/after, ablation, HTTP
docs/                ARCHITECTURE.md, THREAT_MODEL.md, DEMO_SCRIPT.md
```

## Tests

`python3 -m unittest discover -s tests -t .` runs 84 tests in under two seconds:

- **Before/after:** every attack causes harm without AgentShield, and none does with it. Decision sequences match each scenario's `expected_protected`, and benign tasks still complete.
- **Policy rules:** every rule's ALLOW, REQUIRE_APPROVAL and DENY paths.
- **Fail closed:** unknown tool, bad types, NaN or infinite amounts, extra arguments, forged session, spoofed agent, missing or malformed policy file, a rule that throws, and an engine that returns garbage.
- **Approvals:** nothing executes while pending. Agents can't approve. Approvals expire, are void if the call changes, run only once, and can't override a later DENY.
- **Execution grants:** no grant, a forged grant, a grant for a different call, and grant replay are all refused.
- **Audit:** modification, deletion, reordering and a recomputed chain without the key are all detected, and secrets are redacted.
- **Ablation:** both prompt-injection attacks stay contained with any single rule disabled.
- **Fuzzer:** every variant is live without the shield and contained with it. Detection covers every class AgentShield decodes, and obfuscated values are still tainted.
- **Red team:** the loop finds exactly the blind classes. Its proposals close them without adding false positives, its generated regression tests pass, and the live policy stays untouched.
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

## Prior work and attribution

AgentShield's code is original. These ideas shaped its design and are credited here:

- **OWASP Top 10 for LLM Applications (2025):** LLM01 *Prompt Injection* and LLM06 *Excessive Agency* are the two risks this project targets. LLM02 *Sensitive Information Disclosure* motivates the DLP and data-classification rules.
- **Greshake et al., 2023**, "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection" (arXiv:2302.12173). This paper defined indirect prompt injection through retrieved content, the threat behind the document and KB scenarios.
- **Debenedetti et al., 2025**, "Defeating Prompt Injections by Design" (CaMeL, arXiv:2503.18813). It argues for separating control flow from untrusted data and enforcing capabilities outside the model. AgentShield's provenance (taint) rule on control arguments follows that principle in a much simpler, value-based form.
- **Debenedetti et al., 2024**, "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents" (NeurIPS Datasets and Benchmarks). It inspired the shape of the evaluation: utility under attack measured on simulated tools. No AgentDojo code or tasks are used.
- **Invariant Labs, 2025**, "MCP Security Notification: Tool Poisoning Attacks". It describes injections hidden in tool descriptions and "rug-pull" description changes, and motivates the optional manifest-pinning extension.
- **ASCII smuggling** with Unicode tag characters is a publicly documented technique, reproduced here only with synthetic payloads.

Everything else is ours: the policy engine, the gateway, the grants, the audit chain, the fuzzer, the red-team loop and the dashboard. All attack data is synthetic and every test runs locally.

## Attribution

All application and security logic was written from scratch for this hackathon. Runtime dependencies are the Python standard library only. The dashboard uses the Inter and JetBrains Mono typefaces from Google Fonts (SIL Open Font License) and falls back to system fonts offline. Playwright was used only during development to screenshot the dashboard and is not a dependency.
