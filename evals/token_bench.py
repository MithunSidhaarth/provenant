"""Token-efficiency benchmark: the same scripted coding-agent trace, run twice through provenant-tools.

    python evals/token_bench.py         # writes docs/eval/token_benchmark.json and docs/eval/TOKEN_BENCHMARK.md
    python evals/token_bench.py --dump trace.json   # also saves every tool result, for a real tokenizer:
    node evals/count_tokens.mjs trace.json          # (see that file) recounts with BPE tokenizers

baseline   ToolGateway with efficiency off: raw tool output (still policy-checked, as in any Provenant run)
provenant  ToolGateway with compression, safe caching and dedup on

The workload is a fixed trace an agent would plausibly issue while investigating this repository (list,
search, read, re-read, run tests, read again after an edit). It runs on a snapshot of the repository in a
temp directory. Each step names facts the agent needs from that step; if the shaped output does not contain
them (for example the middle of a long file was elided), the agent makes the follow-up call a real agent would
(a narrower read with offset/limit, or full: true), and those extra calls and tokens are counted.

Tokens are ESTIMATED as ceil(characters / 4); characters are exact. "Context tokens" are the tool-result
tokens that enter the model's context. "Re-read input tokens" assumes every step's model call re-sends the
whole context so far without prompt caching, which is how cost grows in a long agent loop. Task success means
every needed fact was obtained. This is one workload; other workloads will save more or less, or nothing.
"""
from __future__ import annotations

import json
import math
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agentshield.efficiency import Efficiency  # noqa: E402
from agentshield.guard import Guard, Store  # noqa: E402
from agentshield.tool_server import ToolGateway  # noqa: E402

TRACE = [
    ("list_directory", {"path": ".", "depth": 2}, ["agentshield/", "tests/"]),
    ("read_file", {"path": "agentshield/guard.py"}, ["class Guard", "self.store.db.consume_approval("]),
    ("search_text", {"pattern": r"def (check|redeem|decide)\(", "path": "agentshield"}, ["guard.py"]),
    ("read_file", {"path": "agentshield/state.py"}, ["def consume_approval", "if cur.rowcount != 1"]),
    ("run_tests", {}, ["Ran ", "OK"]),
    ("read_file", {"path": "agentshield/models.py"}, ["def fingerprint"]),
    ("read_file", {"path": "agentshield/guard.py"}, ["redeem_grant(verdict.grant_id"]),
    ("search_text", {"pattern": "fingerprint", "path": "agentshield"}, ["state.py"]),
    ("list_directory", {"path": "agentshield", "depth": 1}, ["guard.py"]),
    ("read_file", {"path": "agentshield/state.py"}, ["redeemed_at IS NULL"]),
    ("read_file", {"path": "tests/test_live.py"}, ["def test_concurrent_consumers_only_one_wins"]),
    ("EDIT", {"path": "agentshield/models.py"}, []),
    ("read_file", {"path": "agentshield/models.py"}, ["benchmark edit"]),
    ("run_tests", {}, ["Ran ", "OK"]),
    ("read_file", {"path": "agentshield/guard.py"}, ["obfuscation_signals(text, scan_injection)"]),
    ("list_directory", {"path": ".", "depth": 2}, ["evals/"]),
]


def est(s: str) -> int:
    return math.ceil(len(s) / 4)


def run(mode: str, ws: Path) -> dict:
    with tempfile.TemporaryDirectory() as home:
        guard = Guard(store=Store(Path(home), mode="live"))
        gw = ToolGateway(str(ws), guard=guard, efficiency=Efficiency(enabled=mode == "provenant"),
                         test_cmd=[sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "."])
        history: dict[int, str] = {}
        ctx = calls = out_tokens = reread = 0
        steps, failures, texts = [], [], []
        t0 = time.perf_counter()
        for i, (tool, args, needs) in enumerate(TRACE):
            if tool == "EDIT":
                p = ws / args["path"]
                p.write_text(p.read_text() + "\n# benchmark edit\n")
                continue
            got, step_ctx, step_calls = "", 0, 0
            request = dict(args)
            for attempt in range(4):
                r = gw.call(tool, request)
                text = r["content"][0]["text"]
                step_calls += 1
                calls += 1
                out_tokens += est(json.dumps({"name": tool, "arguments": request}))
                history[gw.calls] = text
                texts.append({"step": i, "text": text})
                step_ctx += est(text)
                ctx += est(text)
                reread += ctx
                got += "\n" + text
                if "unchanged since your call #" in text:          # the agent still has the earlier result in context
                    n = int(text.split("#")[1].split()[0])
                    got += "\n" + history.get(n, "")
                missing = [n for n in needs if n not in got]
                if not missing:
                    break
                hit_line = next((int(l.split(":")[0]) for l in text.splitlines()
                                 if ":" in l and l.split(":")[0].strip().isdigit() and missing[0] in l), None)
                if tool == "read_file" and "Outline" in text and hit_line:
                    request = {**args, "offset": max(0, hit_line - 3), "limit": 90}
                    continue
                if tool == "read_file" and attempt < 2 and "offset" not in request:
                    hit = gw.call("search_text", {"pattern": re.escape(missing[0]), "path": str(Path(args["path"]).parent), "glob": Path(args["path"]).name})
                    htext = hit["content"][0]["text"]
                    texts.append({"step": i, "text": htext})
                    calls += 1
                    step_calls += 1
                    out_tokens += est(missing[0]) + 20
                    step_ctx += est(htext)
                    ctx += est(htext)
                    reread += ctx
                    m = re.search(r"^\s*(?:[^:\n]+:)?(\d+): ", htext, re.M)    # `path:N: text` or grouped `  N: text`
                    line = int(m.group(1)) if m else 1
                    request = {**args, "offset": max(0, line - 5), "limit": 120}
                else:
                    request = {**args, "full": True}
            ok = all(n in got for n in needs)
            if not ok:
                failures.append({"step": i, "tool": tool, "missing": [n for n in needs if n not in got]})
            steps.append({"step": i, "tool": tool, "calls": step_calls, "context_tokens": step_ctx, "ok": ok})
        return {"mode": mode, "tool_calls": calls, "context_tokens": ctx, "reread_input_tokens": reread,
                "output_tokens": out_tokens, "cache_hits": gw.eff.stats.cache_hits, "dedup_hits": gw.eff.stats.dedup_hits,
                "task_success": not failures, "failures": failures, "wall_seconds": round(time.perf_counter() - t0, 2),
                "steps": steps, "texts": texts}





def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    dump = Path(argv[argv.index("--dump") + 1]) if "--dump" in argv else None
    out = ROOT / "docs" / "eval"
    out.mkdir(parents=True, exist_ok=True)
    results = {}
    for mode in ("baseline", "provenant"):
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t) / "repo"
            ws.mkdir()
            tar = subprocess.run(["git", "archive", "HEAD"], cwd=ROOT, capture_output=True, check=True).stdout
            subprocess.run(["tar", "-x", "-C", str(ws)], input=tar, check=True)
            results[mode] = run(mode, ws)
    texts = {m: results[m].pop("texts") for m in results}
    if dump:
        dump.write_text(json.dumps(texts))
    b, p = results["baseline"], results["provenant"]

    def delta(k):
        return {"baseline": b[k], "provenant": p[k], "change_pct": round((p[k] - b[k]) / b[k] * 100, 1) if b[k] else None}
    summary = {"workload": f"{len(TRACE) - 1}-step scripted repository investigation (evals/token_bench.py)",
               "token_estimate": "ceil(chars/4)", "context_tokens": delta("context_tokens"),
               "reread_input_tokens": delta("reread_input_tokens"), "output_tokens": delta("output_tokens"),
               "tool_calls": delta("tool_calls"), "cache_hits": p["cache_hits"], "dedup_hits": p["dedup_hits"],
               "task_success": {"baseline": b["task_success"], "provenant": p["task_success"]},
               "wall_seconds": {"baseline": b["wall_seconds"], "provenant": p["wall_seconds"]},
               "policy_llm_calls": 0}
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    doc = {"generated_utc": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), "commit": commit, "summary": summary,
           "runs": results}
    (out / "token_benchmark.json").write_text(json.dumps(doc, indent=1))
    rows = [("Context tokens (tool results)", "context_tokens"), ("Re-read input tokens (no prompt cache)", "reread_input_tokens"),
            ("Output tokens (tool-call JSON)", "output_tokens"), ("Tool calls", "tool_calls")]
    md = ["# Token-efficiency benchmark", "",
          f"Generated {doc['generated_utc']} at commit `{commit}` by `python evals/token_bench.py`.", "",
          f"Workload: {summary['workload']}. Both runs go through the same policy checks; only compression, caching and "
          "dedup differ. Tokens are estimated as ceil(characters / 4); one workload, not a guarantee for others.", "",
          "| Metric | Baseline | Provenant | Change |", "|---|---|---|---|"]
    for label, k in rows:
        d = summary[k]
        md.append(f"| {label} | {d['baseline']:,} | {d['provenant']:,} | {d['change_pct']:+.1f}% |")
    md += [f"| Cache hits | 0 | {p['cache_hits']} | |", f"| Dedup references | 0 | {p['dedup_hits']} | |",
           f"| Task success | {b['task_success']} | {p['task_success']} | |",
           f"| Extra LLM calls for policy | 0 | 0 | |", "",
           "Follow-up calls caused by elided output are included in the Provenant numbers."]
    if p["failures"] or b["failures"]:
        md += ["", "Failures: " + json.dumps({"baseline": b["failures"], "provenant": p["failures"]})]
    (out / "TOKEN_BENCHMARK.md").write_text("\n".join(md) + "\n")
    print(json.dumps(summary, indent=1))
    return 0 if p["task_success"] and b["task_success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
