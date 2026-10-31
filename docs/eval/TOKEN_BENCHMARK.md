# Token-efficiency benchmark

Generated 2026-10-31 05:53 UTC at commit `1acdea4` by `python evals/token_bench.py`.

Workload: 15-step scripted repository investigation (evals/token_bench.py). Both runs go through the same policy checks; only compression, caching and dedup differ. Tokens are estimated as ceil(characters / 4); one workload, not a guarantee for others.

| Metric | Baseline | Provenant | Change |
|---|---|---|---|
| Context tokens (tool results) | 59,707 | 15,778 | -73.6% |
| Re-read input tokens (no prompt cache) | 478,280 | 195,965 | -59.0% |
| Output tokens (tool-call JSON) | 259 | 421 | +62.5% |
| Tool calls | 15 | 21 | +40.0% |
| Cache hits | 0 | 3 | |
| Dedup references | 0 | 3 | |
| Task success | True | True | |
| Extra LLM calls for policy | 0 | 0 | |

Follow-up calls caused by elided output are included in the Provenant numbers. A recount with real tokenizers (evals/count_tokens.mjs), what the saving applies to and its limits: docs/TOKENS.md.
