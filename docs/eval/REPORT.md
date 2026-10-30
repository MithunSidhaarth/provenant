# Provenant security evaluation

Generated 2026-10-30 17:43 UTC by `python evals/run_eval.py` at commit `6d3e06f`, policy `guard-2026.10-3`, Python 3.13.17 on Linux-6.18.44-fc-v185-x86_64-with-glibc2.39.

Passing these cases is evidence of coverage for the cases listed, not proof that no bypass exists.

## Policy corpus

- Attacks (negative controls): **128/128 contained** (never ALLOW); 128/128 got exactly the expected decision. Decisions: {'DENY': 110, 'REQUIRE_APPROVAL': 18}.
- Legitimate actions (positive controls): **35/35** decided as expected; no false positives.
- Saved policy scenarios: 32/32.
- Decision latency (no model call): p50 0.138 ms, p95 0.457 ms, max 2.616 ms over 975 evaluations.

| Category | Attacks | Contained |
|---|---|---|
| shell | 44 | 44 |
| rce | 10 | 10 |
| path | 19 | 19 |
| tamper | 11 | 11 |
| ssrf | 19 | 19 |
| dlp | 9 | 9 |
| taint | 6 | 6 |
| classify | 6 | 6 |
| failclosed | 4 | 4 |

## Live integration (real processes)

| Check | Result |
|---|---|
| allowed command really runs | pass |
| rm -rf on the workspace never reaches the server | pass |
| secret file read is denied and not leaked | pass |
| write outside the workspace never lands | pass |
| notification-shaped tools/call is dropped | pass |
| unknown JSON-RPC method refused | pass |
| malformed JSON gets a parse error | pass |
| risky call is held for a human, nothing runs | pass |
| audit chain verifies after the run | pass |

Per-call latency, same `read_file` call, 50 samples after warm-up: direct p50 0.08 ms, through Provenant p50 13.56 ms (p95 17.82 ms). Overhead p50 ≈ 13.48 ms per call, which includes the SQLite writes and audit appends.

## Unit and integration tests

166/166 passed in 6.7 s.

| Area | Tests | Passed |
|---|---|---|
| simulated world (policy engine, fuzzer, scenarios, server) | 97 | 97 |
| audit hash chain | 9 | 9 |
| real-tool policy rules | 13 | 13 |
| authorization state, grants, concurrency, fail-closed | 9 | 9 |
| audit anchoring and retention | 4 | 4 |
| network destinations (IPv4/IPv6 forms, rebinding, redirects) | 4 | 4 |
| phone approval validation | 6 | 6 |
| policy simulator and lint | 2 | 2 |
| audit privacy and redaction | 2 | 2 |
| gateway tool server, cache/dedup, MCP lifecycle | 7 | 7 |
| real MCP proxy and Claude Code hook (subprocesses) | 13 | 13 |

## Resources

Peak RSS 38.4 MB, CPU 1.99 s, wall 8.2 s for the whole evaluation.

## Token efficiency

See `docs/eval/TOKEN_BENCHMARK.md`.

## Known gaps

- Shell analysis is pattern-based: an agent can write a script and then run it, or use an allowed interpreter.
- Provenance is value-based: paraphrased, encoded, split or transformed destinations can evade it.
- Secret detection is pattern-based: unknown key formats and secrets split or encoded in new ways can pass.
- Destination pinning applies to requests Provenant makes (http_get); other clients are judged by URL text only.
- Approvals over the CLI need a TTY: a speed bump against an agent, not a proof of a human.
- Remote (HTTP/SSE) MCP servers are not proxied; only stdio servers are.
- Single-user: state, keys and approvals are per OS user; shared multi-tenant hosting is not supported.
