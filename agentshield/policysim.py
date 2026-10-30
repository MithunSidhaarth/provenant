"""Policy simulator and diagnostics: try a policy against saved scenarios before it guards real tools.

    provenant policy test [scenarios.json] [--policy FILE]   expected vs actual decision, with the deciding rules
    provenant policy lint [--policy FILE]                      shadowed rules, overlaps, overbroad settings
    provenant policy explain TOOL ARGS_JSON [--policy FILE]    every finding for one call

Evaluation uses the same GuardPolicy.evaluate as the runtime, on a throwaway in-memory session, so a passing
simulation means the runtime would decide the same for those inputs. It is not exhaustive verification: lint
finds the classes of mistake listed below, and only scenarios you save are regression-tested.

Lint checks:
  shadowed     a `tools` pattern that can never match because an earlier pattern matches everything it does
  overlap      a tool name pattern listed under more than one category (the first category in
               shell, read-verb, write, send, network, read order wins; the others are unreachable for it)
  overbroad    ALLOW for '*', unknown_tool ALLOW, wildcard network hosts, empty secret patterns,
               outside-workspace writes not DENY, missing approval TTL or very long TTL
"""
from __future__ import annotations

import fnmatch
import json
import sys
from pathlib import Path

from .guard import CATEGORY_ORDER, DEFAULT_GUARD_POLICY, GuardCall, GuardPolicy
from .models import Decision

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCENARIOS = ROOT / "evals" / "policy_scenarios.json"


def _session() -> dict:
    return {"session_id": "sim", "user_texts": [], "untrusted_texts": [], "injection_flags": [], "call_count": 0}


def explain(policy: GuardPolicy, tool, args, workspace: str = "/work", session: dict | None = None) -> dict:
    res = policy.evaluate(GuardCall(tool, args, "sim", workspace, "sim"), session or _session())
    deciding = [f.to_dict() for f in res.findings if f.decision == res.decision and f.rule not in ("default",)]
    return {"decision": res.decision.value, "deciding": deciding, "findings": [f.to_dict() for f in res.findings]}


def run_scenarios(policy: GuardPolicy, scenarios: list[dict]) -> dict:
    rows = []
    for sc in scenarios:
        session = _session()
        session["untrusted_texts"] = [t.lower() for t in sc.get("untrusted", [])]
        session["user_texts"] = sc.get("user", [])
        if sc.get("injection_seen"):
            session["injection_flags"] = [{"label": "scenario"}]
        r = explain(policy, sc["tool"], sc.get("args", {}), sc.get("workspace", "/work"), session)
        rows.append({"name": sc.get("name", sc["tool"]), "expect": sc["expect"], "actual": r["decision"],
                     "pass": r["decision"] == sc["expect"],
                     "why": [f"{f['rule']}: {f['reason']}" for f in r["deciding"]][:3]})
    return {"total": len(rows), "passed": sum(r["pass"] for r in rows), "rows": rows}


def _subsumes(a: str, b: str) -> bool:
    """Does glob a match every string glob b can match? Conservative: literal or '*'-suffix/prefix cases."""
    if a == b or a == "*":
        return True
    if not any(c in b for c in "*?["):
        return fnmatch.fnmatchcase(b, a)
    if a.startswith("*") and a.endswith("*") and a.count("*") == 2:
        return a[1:-1] in b.replace("*", "")
    return False


def lint(policy: GuardPolicy) -> list[dict]:
    if policy.load_error:
        return [{"level": "error", "check": "load", "message": policy.load_error}]
    c, out = policy.config, []
    tools = list(c["tools"].items())
    for i, (pat, dec) in enumerate(tools):
        for earlier, edec in tools[:i]:
            if _subsumes(earlier, pat):
                out.append({"level": "warn", "check": "shadowed",
                            "message": f"tools['{pat}'] ({dec}) is unreachable: '{earlier}' ({edec}) matches first"})
                break
        if pat in ("*", "mcp__*") and Decision(dec) == Decision.ALLOW:
            out.append({"level": "error", "check": "overbroad", "message": f"tools['{pat}'] = ALLOW allows every tool"})
    cats = c["categories"]
    seen: dict[str, str] = {}
    for cat in CATEGORY_ORDER:
        for pat in cats.get(cat, []):
            if pat in seen and seen[pat] != cat:
                out.append({"level": "info", "check": "overlap",
                            "message": f"pattern '{pat}' is in both '{seen[pat]}' and '{cat}'; '{seen[pat]}' wins"})
            seen.setdefault(pat, cat)
    for cat in CATEGORY_ORDER:
        for pat in cats.get(cat, []):
            for other in CATEGORY_ORDER[:CATEGORY_ORDER.index(cat)]:
                for op in cats.get(other, []):
                    if op != pat and _subsumes(op, pat):
                        out.append({"level": "info", "check": "overlap",
                                    "message": f"{cat} pattern '{pat}' is always caught first by {other} pattern '{op}'"})
    if Decision(c["unknown_tool"]) == Decision.ALLOW:
        out.append({"level": "error", "check": "overbroad", "message": "unknown_tool is ALLOW: unclassified tools run unchecked"})
    if any(h in ("*", "*.*", "*.com") for h in c["network"]["allowed_hosts"]):
        out.append({"level": "error", "check": "overbroad", "message": "allowed_hosts contains a catch-all wildcard"})
    if Decision(c["network"]["unlisted_host"]) == Decision.ALLOW:
        out.append({"level": "warn", "check": "overbroad", "message": "unlisted hosts are ALLOWed (allow-list has no effect)"})
    if not c["paths"].get("secret_patterns"):
        out.append({"level": "error", "check": "overbroad", "message": "no secret_patterns: credential files are readable"})
    if Decision(c["paths"]["outside_workspace_write"]) != Decision.DENY:
        out.append({"level": "warn", "check": "overbroad", "message": "writes outside the workspace are not DENY"})
    ttl = c.get("approval_ttl_seconds")
    if ttl is None or float(ttl) > 3600:
        out.append({"level": "warn", "check": "overbroad", "message": "approval TTL is missing or longer than an hour"})
    if c.get("audit_detail", "minimal") == "full":
        out.append({"level": "info", "check": "privacy", "message": "audit_detail is 'full': tool arguments are stored"})
    return out


def main(argv: list[str]) -> int:
    pol_path = None
    if "--policy" in argv:
        i = argv.index("--policy")
        pol_path, argv = argv[i + 1], argv[:i] + argv[i + 2:]
    policy = GuardPolicy.from_file(pol_path or DEFAULT_GUARD_POLICY)
    sub = argv[0] if argv else "test"
    if sub == "lint":
        issues = lint(policy)
        for i in issues:
            print(f"{i['level']:<5} {i['check']:<10} {i['message']}")
        print(f"{len(issues)} finding(s)")
        return 1 if any(i["level"] == "error" for i in issues) else 0
    if sub == "explain":
        r = explain(policy, argv[1], json.loads(argv[2] if len(argv) > 2 else "{}"))
        print(r["decision"])
        for f in r["findings"]:
            print(f"  {f['decision']:<16} {f['rule']:<18} {f['reason']}")
        return 0
    if sub == "test":
        path = Path(argv[1]) if len(argv) > 1 else DEFAULT_SCENARIOS
        r = run_scenarios(policy, json.loads(path.read_text(encoding="utf-8")))
        for row in r["rows"]:
            mark = "pass" if row["pass"] else "FAIL"
            print(f"{mark}  {row['expect']:<16} {row['actual']:<16} {row['name']}")
            if not row["pass"]:
                for w in row["why"]:
                    print(f"        {w}")
        print(f"{r['passed']}/{r['total']} scenarios match")
        return 0 if r["passed"] == r["total"] else 1
    print("usage: provenant policy test|lint|explain ...", file=sys.stderr)
    return 2
