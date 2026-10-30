# Provenant Mail Security

Provenant inspects structured email messages returned by tools behind a local stdio MCP proxy. It looks for prompt-injection text, urgent credential/payment requests, sender/Reply-To mismatches, URL shorteners, insecure links, external link domains, and known-brand/domain mismatches.

## Setup on Windows

Run once in PowerShell after installing Provenant:

```powershell
provenant mail setup
provenant mail status
```

Setup prompts for a Bolna API key using hidden input and asks for a phone number in international format, such as +919876543210. It stores these settings as current-user environment variables in the Windows user registry. It does not install the separate \`claude-call-me\` skill or modify Claude Code hooks.

## Test and control calls

```powershell
provenant mail test       # asks before placing a real, credit-consuming test call
provenant mail disable    # stop calls; scanning remains active
provenant mail enable     # re-enable high-risk alerts
```

High-risk messages are logged to the Provenant audit chain and trigger an asynchronous Bolna phone alert when calls are enabled. Alerts contain only sender domain, subject, and risk reasons—not the email body, links, or attachments. A short in-memory deduplication set reduces repeat calls during one proxy process. Bolna trial accounts may require the recipient number to be verified.

## Scope and limits

- The scanner processes mail-like records in MCP results. It does not independently connect to a mailbox or fetch messages.
- The connector must be a local stdio MCP server wrapped by Provenant; cloud-hosted connectors that bypass the local proxy are not inspected.
- Detection is heuristic. A low-risk verdict does not prove a message is safe, and a high-risk verdict is not a definitive phishing determination.
- The scanner never opens links, downloads attachments, changes mail, or approves actions. Email content remains untrusted data.
- Phone calls use Bolna and its configured speech/LLM providers and may incur usage charges.
