# Does Provenant reduce an agent's token usage?

Short answer: **yes, when the agent uses Provenant's own tool server (`provenant serve`)**, and only for the tool
results that server returns. On our 15-step benchmark, tool-result tokens entering the model's context fell about
73%, recounted with real tokenizers, and the task still succeeded. The guard hook and the MCP proxy, which sit in
front of the agent's existing tools, do not shrink those tools' output, so on their own they save nothing beyond
the output of calls they block.

## Where the saving comes from

All of it is in `agentshield/efficiency.py`, applied after the policy check on every call (authorization is never
cached):

| Mechanism | What the agent gets instead of the raw output |
|---|---|
| Outline reads | A file over 16,000 characters comes back as its definitions with line numbers plus the first 40 lines. The agent then reads the range it needs with `offset`/`limit`, or asks for `full: true`. |
| Test output | Failures, tracebacks and the summary line; progress dots and passing-test lines are dropped. |
| Dedup | Re-reading an unchanged file in the same session returns a one-line reference to the earlier call. |
| Safe cache | Read-only tools only, keyed by tool, arguments, session, mode, policy version and file size and mtime. Saves work, not tokens. |
| Grouped search | Matches are printed under their file, so a path appears once instead of on every match line. |
| Tree listings | Directory listings print each folder once and indent its entries, instead of repeating the full path. |
| Skipped folders | `.git`, `node_modules`, `dist`, virtualenvs and similar are listed as `[skipped]`, not walked. |

The policy check itself costs zero model calls: it is deterministic code, so Provenant never adds an LLM round
trip to decide anything.

## What it costs

- **More, smaller calls.** When an outline hides the part the agent needs, the agent makes a follow-up read. The
  benchmark counts those: 21 tool calls instead of 15.
- **More output tokens.** The follow-up calls add tool-call JSON: 421 instead of 259 tokens (estimated).
- **Round trips.** Each extra call is another model turn. Cumulative input still falls (about 59%, see below),
  but latency can rise.
- **Tool definitions.** The server's six tool schemas are sent with every request, as any MCP server's are.

## Measured

`python evals/token_bench.py` runs one scripted 15-step investigation of this repository twice through the same
gateway and policy checks: once with efficiency off (baseline, raw tool output) and once on. Each step lists facts
the agent needs; if the shaped output hides one, the run makes the follow-up call a real agent would and counts it.

Recount of the same run with real tokenizers (`evals/count_tokens.mjs`), 2026-10-31. The workload reads this repository, so the counts move by a fraction of a percent as the code changes:

| Tokenizer | Metric | Baseline | Provenant | Change |
|---|---|---|---|---|
| chars/4 estimate | Tool-result tokens | 59,779 | 15,832 | -73.5% |
| chars/4 estimate | Re-read input (no cache) | 478,854 | 196,555 | -59.0% |
| Claude legacy BPE | Tool-result tokens | 68,112 | 18,198 | -73.3% |
| Claude legacy BPE | Re-read input (no cache) | 544,079 | 221,977 | -59.2% |
| o200k_base BPE | Tool-result tokens | 62,152 | 16,878 | -72.8% |
| o200k_base BPE | Re-read input (no cache) | 497,053 | 205,594 | -58.6% |

Grouped search and tree listings were added on 2026-10-31. On the same repository snapshot they cut Provenant's
tool-result tokens from 19,016 to 18,049 (Claude legacy BPE), about 5% more; the overall reduction went from about
72% to about 73%.

## Limits of this evidence

- **One workload**, written by us. Repositories with short files, or tasks that need whole files, will save less
  or nothing. Long logs, big test suites and repeated reads save the most.
- **Not the billed count.** `@anthropic-ai/tokenizer` is Anthropic's legacy (pre-Claude 3) tokenizer, and o200k_base
  is OpenAI's. They agree with each other and with chars/4 to within a point, but current Claude models tokenize
  differently. The authoritative check is the Claude API's `messages/count_tokens` endpoint, which this benchmark
  has not been run against yet.
- **Scripted agent.** The trace is fixed, not a live model choosing its own calls, so it does not show whether a
  real model would make more or fewer follow-ups.
- **Re-read input** assumes no prompt caching. With caching, earlier context is billed at a discount, so the
  saving in cost is smaller than the saving in tokens.
- **The baseline is a raw tool server**, not a specific agent's built-in tools, which may already truncate long
  output.

## Reproduce

```
python evals/token_bench.py --dump trace.json
npm i --prefix /tmp/tok @anthropic-ai/tokenizer@0.0.4 gpt-tokenizer@2.9.0
NODE_PATH=/tmp/tok/node_modules node evals/count_tokens.mjs trace.json
```

The test step runs the full unit suite twice per mode, so a run takes about two minutes.
