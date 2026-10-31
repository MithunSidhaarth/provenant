# Q&A bank

Rule: answer in two sentences, then stop. If you don't know, say "We haven't measured that" and hand it to the owner. Owner in brackets.

## Product and impact [P1]

**Who is this for?** Developers running agents with real tools (Claude Code, Cursor, Claude Desktop), and teams putting agents on email and documents. It installs in one line and changes nothing in the agent.

**Isn't this just a permissions prompt?** A permissions prompt asks a human about everything, so people learn to click yes. Provenant decides most calls itself and only asks when a call is actually risky, with the reason shown.

**What is new here?** The policy is deterministic and sits outside the model; provenance tracking stops data from going to addresses the agent only read about; and the whole thing is measured with a red-team corpus that we regenerate from code.

**Business model?** Open source, local-first. A team version would add a shared policy, central audit and approvals on phone or chat. That is a plan, not built.

## Architecture and security [P2]

**What if the attacker paraphrases the address?** Provenance is value-based, so a reworded address can slip that one rule. The injection-context rule still holds every side effect for a human after injected text is read.

**Can the agent just write a script and run it?** Shell analysis is pattern-based, so that is a real limit. Writing files and running commands are judged separately, and credential files, root deletes and pipe-to-shell are caught either way.

**Why not an LLM judge?** The same injected text can fool an LLM judge. Ours is optional, off by default, and can only escalate.

**Can the agent approve its own call?** `provenant approve` refuses without a real terminal, and the dashboard never approves. With a full PTY an agent could still type it, so we call it a speed bump.

**Is the audit log tamper-proof?** Tamper-evident. Any edit breaks the chain and `audit verify` reports where; truncation needs an external checkpoint (`provenant audit checkpoint`).

**Performance?** Policy decision p50 about 0.16 ms. Proxy overhead p50 roughly 15 to 25 ms per call, depending on the machine (it includes the database and audit writes).

**Remote MCP servers?** Not yet; stdio only.

**What about the MCP rug pull?** Tool definitions are pinned by HMAC on first use. A changed definition is withheld until someone re-approves it.

## Demo, evaluation and limits [P3]

**Is the call real?** Yes: a real Bolna voice call to my phone, placed only with `--call` and a yes. The email is fake on purpose (reserved .example domains).

**How did you test it?** 225 attack cases across 18 categories, 53 legitimate actions, 32 policy scenarios and 9 live proxy checks, all from `python evals/run_eval.py`. Plus 235 unit tests, including installing the wheel in a clean environment.

**Who wrote the attacks? Isn't that circular?** We did, so it is evidence for these cases, not proof. Round 2 was written to break our own v8 guard and found 41 gaps, all fixed.

**False positives?** 0 of 53 legitimate actions blocked in the corpus. Real-world false-positive rates are not measured yet.

**What isn't done?** Phone approval for held calls hasn't run with a real call; the Windows one-line installer hasn't been run on a fresh Windows machine; remote MCP isn't proxied.

**Does it need the internet?** No. Everything is local except the optional phone call.
