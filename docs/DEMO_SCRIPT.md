# Five-minute live demo

Start with `python3 -m agentshield.server` and open http://127.0.0.1:8765/. Click **Reset demo** first.

**0:00 · Framing (20s).** "Agents read things we don't control. We built the worst-case agent: it obeys any instruction it finds in a document. AgentShield keeps it safe anyway, because the model is never the security boundary."

**0:20 · Document injection (90s).** *Attack replay → Prompt injection hidden in a document → Run before / after.*
- On the left, the purple highlighted lines are the hidden HTML comment in the invoice. With no enforcement, the agent reads the DB password and emails it to `northwind-billing.example`. The outcome panel, verified from world state, shows the canary in an outbound email.
- On the right, the same agent with the same injection gets two DENYs. Open the evidence on `send_email`: four independent reasons, which are an external domain, a recipient that came from the document and not the user, injection indicators, and the high-impact rule. "Any one of these alone would have stopped it."

**1:50 · Retrieval injection plus a legitimate action (60s).** *Prompt injection in retrieved KB content.*
- The injected 4999 refund and the attacker beacon are denied. The user's own 20 refund is **held**, not denied. Click **Approve**: it's re-checked and executes once, and the world now shows exactly one 20 refund.

**2:50 · Fail closed (30s).** *Malformed and spoofed tool calls.* Six broken or spoofed calls, six DENYs, each with a reason. The baseline happily executed the spoofed-agent refund.

**3:00 · Attack Lab (bring a judge in, 60s).** *Attack Lab:* "Type your own injection, in any language or encoding." Use the Hindi or invisible-text sample if nobody volunteers. Then click **Run 84-variant campaign**: 84 of 84 live without the shield, 100% contained with it, detection 86% with the blind spots shown. Click **Find gaps and propose fixes**: the loop reproduces the ROT13 gap, proposes a decoder, replays it at 100% with no new false positives, and writes the regression test. "It finds its own gaps, and a human approves the fix."

**3:20 · Tamper evidence (40s).** *Audit trail → Verify chain → Forge a log entry.* "An attacker flips a DENY to ALLOW. The verifier pinpoints the entry, and the real log still verifies."

**4:00 · Defense in depth (30s).** *Defense in depth → Run ablation.* Remove any one rule and both injection attacks stay contained. "We're also honest about where a single rule is load-bearing: that red cell."

**4:30 · Close (30s).** *Policy playground → DLP: canary secret in body → Evaluate.* Then: "Deterministic, auditable, and no model API needed. 73 tests, all synthetic, all inside the sandbox."

Backup if the browser fails: `python3 -m agentshield.demo -v`.
