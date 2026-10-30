"""Provenant security evaluation: reproducible, local, standard library only.

    python evals/run_eval.py            # writes docs/eval/results.json, docs/eval/REPORT.md, docs/guard_redteam.json

Sections
  1. policy corpus     evals/attacks.json (negative controls), evals/benign.json (positive controls) and
                       evals/policy_scenarios.json, evaluated by the runtime GuardPolicy; per-category results
                       and decision latency
  2. live integration  a real MCP server behind the real proxy (subprocesses, temp dirs): allowed calls run,
                       dangerous calls never reach the server (checked on disk), protocol bypasses, malformed
                       input; per-call overhead of the proxy against the same server called directly
  3. test suite        every unittest module, grouped by area (state and concurrency, phone approval, network,
                       gateway, audit, privacy, simulator, proxy, simulated world)
  4. resources         peak RSS and CPU time of this run
Passing is evidence about the cases listed here, not proof that no other bypass exists.
"""
from __future__ import annotations

import json
import os
import platform
import resource
import statistics
import subprocess
import sys
import tempfile
import time
import unittest
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agentshield.guard import DEFAULT_GUARD_POLICY, GuardCall, GuardPolicy  # noqa: E402

OUT = ROOT / "docs" / "eval"


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def session_for(a: dict) -> dict:
    return {"session_id": "eval", "user_texts": a.get("user", []),
            "untrusted_texts": [t.lower() for t in a.get("untrusted", [])],
            "injection_flags": [{"label": "eval"}] if a.get("injection_seen") else [], "call_count": 0}


# Fake credentials are assembled here at run time so no key-shaped string sits in the repository
# (and secret scanners do not flag the corpus). None of these are real.
FAKES = {"aws_access_key": "AKIA" + "Q" * 16, "github_token": "ghp_" + "x" * 36, "anthropic_key": "sk-ant-api03-" + "y" * 30,
         "private_key": "-----BEGIN RSA " + "PRIVATE KEY", "stripe_live_key": "sk_" + "live_" + "z" * 24,
         "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLWZha2U"}


def load_corpus(name: str) -> list[dict]:
    text = (ROOT / "evals" / name).read_text()
    for k, v in FAKES.items():
        text = text.replace("{{fake:%s}}" % k, json.dumps(v)[1:-1])
    return json.loads(text)


def corpus(policy: GuardPolicy) -> dict:
    attacks = load_corpus("attacks.json")
    benign = json.loads((ROOT / "evals" / "benign.json").read_text())
    scen = json.loads((ROOT / "evals" / "policy_scenarios.json").read_text())
    rows, lat = [], []
    for a in attacks + benign + [{**s, "id": "sc_" + s["name"], "category": "scenario", "note": s["name"], "expected": s["expect"]} for s in scen]:
        ws = a.get("workspace", "/work")
        best = None
        for _ in range(5):
            t0 = time.perf_counter()
            res = policy.evaluate(GuardCall(a["tool"], a.get("args", {}), "eval", ws, "eval"), session_for(a))
            dt = (time.perf_counter() - t0) * 1000
            best = dt if best is None else min(best, dt)
            lat.append(dt)
        rows.append({"id": a["id"], "category": a["category"], "note": a.get("note", ""), "tool": a["tool"],
                     "expected": a["expected"], "actual": res.decision.value, "pass": res.decision.value == a["expected"],
                     "reasons": res.reasons[:3], "ms": round(best, 3), "args": _mask(a.get("args"))})
    att = [r for r in rows if r["id"] in {a["id"] for a in attacks}]
    ben = [r for r in rows if r["category"] == "benign"]
    by_cat = defaultdict(lambda: [0, 0])
    for r in att:
        by_cat[r["category"]][0] += 1
        by_cat[r["category"]][1] += r["actual"] != "ALLOW"
    return {
        "attacks": {"total": len(att), "contained": sum(r["actual"] != "ALLOW" for r in att),
                    "exact_match": sum(r["pass"] for r in att),
                    "decisions": dict(Counter(r["actual"] for r in att)),
                    "by_category": [{"category": c, "total": t, "contained": k} for c, (t, k) in by_cat.items()]},
        "benign": {"total": len(ben), "allowed_as_expected": sum(r["pass"] for r in ben),
                   "false_positives": [r["note"] for r in ben if not r["pass"]]},
        "scenarios": {"total": len(scen), "passed": sum(r["pass"] for r in rows if r["category"] == "scenario")},
        "latency_ms": {"p50": round(pct(lat, 50), 3), "p95": round(pct(lat, 95), 3), "max": round(max(lat), 3),
                       "samples": len(lat)},
        "rows": rows,
    }


def _mask(args):
    s = json.dumps(args, ensure_ascii=False)
    if len(s) > 400:
        return {"_truncated": s[:200] + f"... ({len(s)} chars)"}
    from agentshield.guard import redact_secrets
    return json.loads(redact_secrets(s)) if isinstance(args, (dict, list)) else args


class Rpc:
    def __init__(self, argv, env, cwd):
        self.p = subprocess.Popen(argv, env=env, cwd=cwd, text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL)
        self.n = 0

    def raw(self, line: str):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()

    def rpc(self, method, params=None):
        self.n += 1
        self.raw(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}}))
        return json.loads(self.p.stdout.readline())

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)


def live() -> dict:
    checks, timing = [], {}
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        home, ws = t / "home", t / "work"
        ws.mkdir()
        (ws / "keep.txt").write_text("precious")
        (ws / ".env").write_text("STRIPE_KEY=sk_live_" + "9" * 24)
        (ws / "small.txt").write_text("hello\n" * 20)
        env = dict(os.environ, PROVENANT_HOME=str(home), RUG_PULL_FILE=str(t / "rug"), OUTBOX=str(t / "outbox"))
        env.pop("AGENTSHIELD_AUDIT_KEY", None)
        server = [sys.executable, str(ROOT / "tests" / "real_mcp_server.py")]
        proxied = [sys.executable, str(ROOT / "provenant.py"), "proxy", "--name", "eval", "--workspace", str(ws), "--"] + server

        def check(name, ok, detail=""):
            checks.append({"check": name, "pass": bool(ok), "detail": detail})

        px = Rpc(proxied, env, ws)
        px.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "eval"}})
        px.rpc("tools/list")

        def call(name, **a):
            r = px.rpc("tools/call", {"name": name, "arguments": a})
            return r.get("result", {}), (r.get("result", {}).get("content") or [{}])[0].get("text", "")

        _, txt = call("run_command", command="echo provenant-ok")
        check("allowed command really runs", "provenant-ok" in txt)
        call("run_command", command=f"rm -rf {ws}/*")
        check("rm -rf on the workspace never reaches the server", (ws / "keep.txt").exists())
        r, txt = call("read_file", path=str(ws / ".env"))
        check("secret file read is denied and not leaked", txt.startswith("DENY") and "sk_live" not in txt)
        call("write_file", path=str(t / "escape.txt"), content="x")
        check("write outside the workspace never lands", not (t / "escape.txt").exists())
        px.raw(json.dumps({"jsonrpc": "2.0", "method": "tools/call",
                           "params": {"name": "write_file", "arguments": {"path": str(ws / "notif.txt"), "content": "x"}}}))
        px.rpc("tools/list")
        check("notification-shaped tools/call is dropped", not (ws / "notif.txt").exists())
        check("unknown JSON-RPC method refused", px.rpc("admin/exec").get("error", {}).get("code") == -32601)
        px.raw("{not json")
        check("malformed JSON gets a parse error", json.loads(px.p.stdout.readline()).get("error", {}).get("code") == -32700)
        r, txt = call("run_command", command="git push origin main")
        held = (r.get("_meta") or {}).get("provenant", {}).get("approval_id")
        check("risky call is held for a human, nothing runs", txt.startswith("REQUIRE_APPROVAL") and bool(held))

        # overhead: same allowed call, direct vs through the proxy
        direct = Rpc(server, env, ws)
        direct.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "eval"}})
        for label, client in (("direct", direct), ("proxied", px)):
            ts = []
            for i in range(60):
                t0 = time.perf_counter()
                client.rpc("tools/call", {"name": "read_file", "arguments": {"path": str(ws / "small.txt")}})
                ts.append((time.perf_counter() - t0) * 1000)
            timing[label] = {"p50": round(pct(ts[10:], 50), 2), "p95": round(pct(ts[10:], 95), 2),
                             "mean": round(statistics.mean(ts[10:]), 2), "n": len(ts) - 10}
        direct.close()
        px.close()
        out = subprocess.run([sys.executable, str(ROOT / "provenant.py"), "verify"], env=env, capture_output=True, text=True)
        check("audit chain verifies after the run", out.returncode == 0)
    timing["overhead_ms_p50"] = round(timing["proxied"]["p50"] - timing["direct"]["p50"], 2)
    return {"checks": checks, "passed": sum(c["pass"] for c in checks), "total": len(checks), "timing_ms": timing}


AREAS = {
    "test_live.ApprovalState": "authorization state, grants, concurrency, fail-closed",
    "test_live.PhoneApproval": "phone approval validation",
    "test_live.Network": "network destinations (IPv4/IPv6 forms, rebinding, redirects)",
    "test_live.ToolServer": "gateway tool server, cache/dedup, MCP lifecycle",
    "test_live.AuditIntegrity": "audit anchoring and retention",
    "test_live.Privacy": "audit privacy and redaction",
    "test_live.PolicySim": "policy simulator and lint",
    "test_real_proxy": "real MCP proxy and Claude Code hook (subprocesses)",
    "test_guard": "real-tool policy rules",
    "test_audit": "audit hash chain",
}


def suite() -> dict:
    loader = unittest.TestLoader()
    s = loader.discover(str(ROOT / "tests"), top_level_dir=str(ROOT))
    ids = []

    def walk(x):
        for t in x:
            if isinstance(t, unittest.TestSuite):
                walk(t)
            else:
                ids.append(t.id())
    walk(s)
    res = unittest.TestResult()
    t0 = time.time()
    s.run(res)
    failed = {t.id() for t, _ in res.failures + res.errors}
    counts = defaultdict(lambda: [0, 0])
    for full in ids:
        tid = full.removeprefix("tests.")
        area = next((v for k, v in AREAS.items() if tid.startswith(k)), "simulated world (policy engine, fuzzer, scenarios, server)")
        counts[area][0] += 1
        counts[area][1] += full not in failed
    return {"ran": res.testsRun, "failures": len(res.failures), "errors": len(res.errors), "seconds": round(time.time() - t0, 1),
            "by_area": [{"area": a, "tests": n, "passed": p} for a, (n, p) in counts.items()],
            "failed": sorted(failed)}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    policy = GuardPolicy.from_file(DEFAULT_GUARD_POLICY)
    started = time.time()
    c = corpus(policy)
    lv = live()
    st = suite()
    ru = resource.getrusage(resource.RUSAGE_SELF)
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    bench = OUT / "token_benchmark.json"
    result = {
        "generated_utc": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        "environment": {"python": platform.python_version(), "platform": platform.platform(), "commit": commit,
                        "policy_version": policy.version, "cpu_count": os.cpu_count()},
        "corpus": {k: v for k, v in c.items() if k != "rows"},
        "live": lv,
        "unit_tests": st,
        "resources": {"peak_rss_mb": round(ru.ru_maxrss / 1024, 1), "cpu_seconds": round(ru.ru_utime + ru.ru_stime, 2),
                      "wall_seconds": round(time.time() - started, 1)},
        "token_benchmark": json.loads(bench.read_text()) ["summary"] if bench.exists() else None,
        "known_gaps": [
            "Shell analysis is pattern-based: an agent can write a script and then run it, or use an allowed interpreter.",
            "Provenance is value-based: paraphrased, encoded, split or transformed destinations can evade it.",
            "Secret detection is pattern-based: unknown key formats and secrets split or encoded in new ways can pass.",
            "Destination pinning applies to requests Provenant makes (http_get); other clients are judged by URL text only.",
            "Approvals over the CLI need a TTY: a speed bump against an agent, not a proof of a human.",
            "Remote (HTTP/SSE) MCP servers are not proxied; only stdio servers are.",
            "Single-user: state, keys and approvals are per OS user; shared multi-tenant hosting is not supported.",
        ],
    }
    (OUT / "results.json").write_text(json.dumps(result, indent=1))
    (OUT / "corpus_results.json").write_text(json.dumps(c["rows"], indent=1, ensure_ascii=False))
    # the dashboard's red-team panel reads this file; it is regenerated from the current code, never hand-edited
    att = [r for r in c["rows"] if r["category"] not in ("benign", "scenario")]
    (ROOT / "docs" / "guard_redteam.json").write_text(json.dumps({
        "generated": result["generated_utc"], "suite": "evals/run_eval.py (evals/attacks.json)",
        "summary": {"policy_version": policy.version, "total": len(att),
                    "blocked": sum(r["actual"] == "DENY" for r in att), "held": sum(r["actual"] == "REQUIRE_APPROVAL" for r in att),
                    "allowed": sum(r["actual"] == "ALLOW" for r in att), "missed": sum(r["actual"] == "ALLOW" for r in att),
                    "contained": sum(r["actual"] != "ALLOW" for r in att)},
        "by_category": c["attacks"]["by_category"],
        "attacks": [{k: r[k] for k in ("id", "category", "note", "tool", "args", "expected", "actual", "reasons", "pass")} for r in att],
    }, indent=1, ensure_ascii=False))
    write_report(result)
    site = ROOT / "dashboard" / "eval"           # the static site reads these; same files, no hand-edited numbers
    site.mkdir(exist_ok=True)
    for name in ("results.json", "REPORT.md", "token_benchmark.json", "TOKEN_BENCHMARK.md"):
        if (OUT / name).exists():
            (site / name).write_bytes((OUT / name).read_bytes())
    ok = (c["attacks"]["contained"] == c["attacks"]["total"] and not c["benign"]["false_positives"]
          and lv["passed"] == lv["total"] and not st["failed"])
    print(json.dumps({"attacks_contained": f"{c['attacks']['contained']}/{c['attacks']['total']}",
                      "benign_ok": f"{c['benign']['allowed_as_expected']}/{c['benign']['total']}",
                      "live": f"{lv['passed']}/{lv['total']}", "unit": f"{st['ran'] - len(st['failed'])}/{st['ran']}",
                      "policy_p50_ms": c["latency_ms"]["p50"], "proxy_overhead_p50_ms": lv["timing_ms"]["overhead_ms_p50"]}))
    return 0 if ok else 1


def write_report(r: dict) -> None:
    c, lv, st = r["corpus"], r["live"], r["unit_tests"]
    L = [f"# Provenant security evaluation", "",
         f"Generated {r['generated_utc']} by `python evals/run_eval.py` at commit `{r['environment']['commit']}`, "
         f"policy `{r['environment']['policy_version']}`, Python {r['environment']['python']} on {r['environment']['platform']}.",
         "", "Passing these cases is evidence of coverage for the cases listed, not proof that no bypass exists.", "",
         "## Policy corpus", "",
         f"- Attacks (negative controls): **{c['attacks']['contained']}/{c['attacks']['total']} contained** "
         f"(never ALLOW); {c['attacks']['exact_match']}/{c['attacks']['total']} got exactly the expected decision. "
         f"Decisions: {c['attacks']['decisions']}.",
         f"- Legitimate actions (positive controls): **{c['benign']['allowed_as_expected']}/{c['benign']['total']}** decided as expected"
         + (f"; false positives: {c['benign']['false_positives']}" if c['benign']['false_positives'] else "; no false positives") + ".",
         f"- Saved policy scenarios: {c['scenarios']['passed']}/{c['scenarios']['total']}.",
         f"- Decision latency (no model call): p50 {c['latency_ms']['p50']} ms, p95 {c['latency_ms']['p95']} ms, "
         f"max {c['latency_ms']['max']} ms over {c['latency_ms']['samples']} evaluations.", "",
         "| Category | Attacks | Contained |", "|---|---|---|"]
    L += [f"| {b['category']} | {b['total']} | {b['contained']} |" for b in c["attacks"]["by_category"]]
    L += ["", "## Live integration (real processes)", "", "| Check | Result |", "|---|---|"]
    L += [f"| {x['check']} | {'pass' if x['pass'] else 'FAIL'} |" for x in lv["checks"]]
    t = lv["timing_ms"]
    L += ["", f"Per-call latency, same `read_file` call, 50 samples after warm-up: direct p50 {t['direct']['p50']} ms, "
          f"through Provenant p50 {t['proxied']['p50']} ms (p95 {t['proxied']['p95']} ms). "
          f"Overhead p50 ≈ {t['overhead_ms_p50']} ms per call, which includes the SQLite writes and audit appends.", "",
          "## Unit and integration tests", "",
          f"{st['ran'] - len(st['failed'])}/{st['ran']} passed in {st['seconds']} s.", "", "| Area | Tests | Passed |", "|---|---|---|"]
    L += [f"| {a['area']} | {a['tests']} | {a['passed']} |" for a in st["by_area"]]
    rs = r["resources"]
    L += ["", f"## Resources", "", f"Peak RSS {rs['peak_rss_mb']} MB, CPU {rs['cpu_seconds']} s, wall {rs['wall_seconds']} s for the whole evaluation.", ""]
    if r.get("token_benchmark"):
        L += ["## Token efficiency", "", "See `docs/eval/TOKEN_BENCHMARK.md`.", ""]
    L += ["## Known gaps", ""] + [f"- {g}" for g in r["known_gaps"]] + [""]
    (OUT / "REPORT.md").write_text("\n".join(L))


if __name__ == "__main__":
    raise SystemExit(main())
