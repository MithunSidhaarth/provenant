# Mail screening and phone alerts (0.10)

Provenant screens every mail an agent reads through a mail tool (a Gmail MCP server wrapped by `provenant setup`,
or the Claude Code PostToolUse hook for `mcp__*gmail*` style tools) and can phone you about the dangerous ones.

## What happens to each mail
1. The tool result is parsed into mails (Gmail API JSON, simple JSON, JSON inside text blocks, or RFC-style text).
2. Each mail is scored 0-100 from deterministic signals: look-alike or punycode sender/link domains, display-name
   spoofing, link text that differs from its target, shorteners, raw-IP links, `user@host` links, reply-to mismatch,
   failed SPF/DKIM/DMARC, urgency + credential/payment asks, gift-card/crypto/changed-bank-details pressure,
   risky attachments (`.exe`, `.pdf.exe`, macros, `.html`), and prompt injection aimed at the agent.
3. A `mail_verdict` entry goes into the hash-chained audit log: sender, subject, level, score, reasons. Never the body.
4. A **high** mail makes the session distrust itself: later sends, forwards and deletes need a human (same rule as
   prompt injection). Reading is never blocked. The model is not asked.
5. If phone alerts are set up, a high mail triggers one short call (once per mail, at most 3 per batch).

`provenant mail scan FILE|-` checks a saved mail or export by hand; `provenant mail log` lists recent verdicts;
`provenant log -f` shows MAIL HIGH/MEDIUM lines live.

## Phone setup (needs only a Bolna API key)
`provenant setup` asks at the end ("Phone alerts (optional)"). Or run `provenant phone setup`, which asks for the key
(hidden) and your own number (E.164, e.g. +919876543210). Non-interactive: set `PROVENANT_BOLNA_API_KEY` and
`PROVENANT_PHONE`, then `provenant phone setup --from-env`. The key is stored in `~/.provenant/phone.json`
(mode 0600 where supported) or taken from `BOLNA_API_KEY`; it is never printed, audited or sent anywhere but api.bolna.ai.

`provenant phone test` places one real test call. `provenant phone alerts mail on|off`, `... level medium|high`,
`provenant phone forget`. The same caller now also carries phone approval (`provenant call APPROVAL_ID`); the
claude-call-me script is only a fallback. Bolna logic is ported from https://github.com/MithunSidhaarth/claude-call-me.

## Honest limits
- Heuristics, not a mail security product: expect misses (a clean-looking, well-written phish) and some false alarms.
- Only mail that passes through a wrapped local MCP server or the Claude Code hook is seen. A cloud connector that runs
  inside claude.ai does not.
- Tested with fake mails and a fake Bolna client. **No real Bolna call has been placed by this code yet.** The Bolna
  request shapes are copied from the claude-call-me script, which has worked for you.
- Cost: Bolna bills per minute; alerts are capped (once per mail, high only by default).

## Live inbox watch from the dashboard
`provenant dashboard` opens the local console, which starts watching INBOX over IMAP (read-only) right away. Each new
message is scored with `mailscan.score_mail`; medium and high results are listed in "Inbox watch", and results at the
phone alert level (`provenant phone alerts level medium|high`, default high) place a Bolna call (5 an hour at most).
Connect the mailbox once with `provenant mail watch --setup`. The dashboard never asks for the password. Stop it with
the "Stop watching" button; it also stops when the dashboard process exits.
