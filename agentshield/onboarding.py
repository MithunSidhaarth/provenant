"""Onboarding logic behind `provenant status`, `doctor`, `verify` and `rollback`. No printing here: cli.py renders.

Protection is reported in layers, and each layer needs its own evidence:

    installed   this package runs (always true if you can read this)
    engine      the policy loads and the audit chain verifies
    configured  at least one client config routes MCP servers through the proxy, or the Claude Code hook is set
    connected   the audit log shows a client actually sent traffic through Provenant (proxy start or hook decision)
    verified    `provenant verify` ran the safe enforcement self-test against the current policy and it passed

Installing the package alone never reports a client as protected.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import sysconfig
import tempfile
import time
from pathlib import Path

from . import guard as guard_mod
from .models import new_id

LEVELS = ("installed", "engine", "configured", "connected", "verified")
VERIFY_SOURCE = "provenant-verify"


def _cli():
    from . import cli
    return cli


# --- evidence from the audit log -----------------------------------------------------------------
def traffic_evidence(entries: list[dict]) -> dict:
    """Last time each integration actually routed a call through Provenant, from the audit log."""
    seen: dict[str, str] = {}
    for e in entries:
        d = e.get("data") or {}
        if e.get("event") == "proxy_start" and d.get("server"):
            seen[f"mcp:{d['server']}"] = e.get("ts", "")
        elif e.get("event") == "policy_decision" and d.get("source") == "claude-code":
            seen["claude-code"] = e.get("ts", "")
        elif e.get("event") == "policy_decision" and d.get("source") == "provenant-tools":
            seen["provenant-tools"] = e.get("ts", "")
    return seen


def _verify_record_path(home: Path) -> Path:
    return home / "last_verify.json"


def last_verify(home: Path) -> dict | None:
    try:
        return json.loads(_verify_record_path(home).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def protection(status: dict, entries: list[dict], home: Path) -> dict:
    """The layered state shown by `status` and expected by the website. Every layer cites its evidence."""
    configured_servers = {n for c in status["clients"] for n in c["protected"]}
    configured = bool(configured_servers) or status["claude_code_hook"]
    traffic = traffic_evidence(entries)
    connected = [k for k in traffic if k == "claude-code" and status["claude_code_hook"]
                 or k.startswith("mcp:") and k[4:] in configured_servers or k == "provenant-tools"]
    lv = last_verify(home)
    verified = bool(lv and lv.get("passed") and lv.get("policy_version") == status["policy_version"])
    engine = status["audit"]["ok"] and not status["policy_error"]
    layers = {"installed": True, "engine": engine, "configured": configured,
              "connected": bool(connected), "verified": verified}
    level = "installed"
    for name in LEVELS[1:]:
        if not layers[name]:
            break
        level = name
    if not engine:
        nxt = "run provenant doctor"
    elif not configured:
        nxt = "run provenant setup"
    elif not connected:
        nxt = "restart your AI client and let it make one tool call, then run provenant status"
    elif not verified:
        nxt = "run provenant verify"
    else:
        nxt = None
    return {"level": level, "layers": layers, "connected_via": {k: traffic[k] for k in connected},
            "last_verify": lv, "next": nxt,
            "summary": {"installed": "Provenant is installed, but nothing routes through it yet.",
                        "engine": "The local engine works. No AI client is configured to use it yet.",
                        "configured": "A client is configured. Provenant has not seen traffic from it yet.",
                        "connected": "A client is routing tool calls through Provenant.",
                        "verified": "A client routes tool calls through Provenant and the enforcement test passed."}[level]}


# --- verify: the safe enforcement self-test --------------------------------------------------------
def self_test(g: guard_mod.Guard | None = None) -> dict:
    """Prove enforcement with harmless, local, simulated actions. Nothing destructive runs, no secret is read,
    nothing leaves the machine. The 'side effect' of the forbidden action is deleting a canary file in a fresh
    temp folder, and the executor below only performs it if the guard grants the call."""
    g = g or guard_mod.Guard()
    steps: list[dict] = []
    call_ids: list[str] = []
    with tempfile.TemporaryDirectory(prefix="provenant-verify-") as ws:
        hello, canary = Path(ws) / "hello.txt", Path(ws) / "canary.txt"
        hello.write_text("hello from provenant verify\n", encoding="utf-8")
        canary.write_text("if this file disappears, enforcement failed\n", encoding="utf-8")

        def run(tool: str, args: dict) -> tuple:
            call = guard_mod.GuardCall(tool, args, new_id("verify"), ws, VERIFY_SOURCE)
            call_ids.append(call.call_id)
            return call, g.check(call, hold=False)

        # 1. a harmless read is allowed and runs, through a single-use grant
        call, v = run("Read", {"file_path": str(hello)})
        ran = v.decision.value == "ALLOW" and g.redeem(v, call) and hello.read_text(encoding="utf-8").startswith("hello")
        steps.append({"id": "benign_allowed", "action": f"Read {hello.name} (inside a temp folder)",
                      "expected": "ALLOW", "got": v.decision.value, "passed": bool(ran)})

        # 2. the grant is bound to the exact arguments evaluated: swapping them is refused
        call2, v2 = run("Read", {"file_path": str(hello)})
        swapped = guard_mod.GuardCall("Read", {"file_path": str(canary)}, call2.session_id, ws, VERIFY_SOURCE, call2.call_id)
        refused = not g.redeem(v2, swapped)
        steps.append({"id": "exact_args_bound", "action": "Reuse that grant for a different file",
                      "expected": "refused", "got": "refused" if refused else "accepted", "passed": refused})

        # 3. a forbidden action is denied and its simulated side effect never happens
        call3, v3 = run("Bash", {"command": "rm -rf ~"})
        if v3.decision.value == "ALLOW" and g.redeem(v3, call3):
            canary.unlink()                   # simulated side effect, never the real command
        intact = canary.exists()
        steps.append({"id": "unauthorized_denied", "action": "Bash: rm -rf ~ (evaluated only; never executed)",
                      "expected": "DENY", "got": v3.decision.value,
                      "reasons": v3.reasons[:2], "passed": v3.decision.value == "DENY" and intact})
        steps.append({"id": "side_effect_absent", "action": "Check the canary file still exists",
                      "expected": "present", "got": "present" if intact else "deleted", "passed": intact})

        # 4. a high-impact action needs a human (evaluated with hold=False: nothing is queued)
        _, v4 = run("Bash", {"command": "npm publish"})
        steps.append({"id": "approval_required", "action": "Bash: npm publish (evaluated only)",
                      "expected": "REQUIRE_APPROVAL", "got": v4.decision.value, "reasons": v4.reasons[:2],
                      "passed": v4.decision.value == "REQUIRE_APPROVAL"})

    # 5. the decisions are in the tamper-evident audit log, and the chain verifies
    entries = g.audit.snapshot()
    mine = [{"seq": e["seq"], "event": e["event"], "tool": e["data"].get("tool"), "decision": e["data"].get("decision"),
             "hash": e["hash"][:16]} for e in entries
            if e.get("event") == "policy_decision" and e.get("data", {}).get("call_id") in call_ids]
    chain = g.audit.verify()
    steps.append({"id": "audit_recorded", "action": "Find these decisions in the audit log and verify the hash chain",
                  "expected": f"{len(call_ids)} entries, chain intact",
                  "got": f"{len(mine)} entries, chain {'intact' if chain['ok'] else 'BROKEN'}",
                  "passed": len(mine) == len(call_ids) and chain["ok"]})
    passed = all(s["passed"] for s in steps)
    record = {"passed": passed, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "policy_version": g.policy.version, "mode": g.mode}
    try:
        _verify_record_path(g.store.home).write_text(json.dumps(record), encoding="utf-8")
    except OSError:
        pass
    return {**record, "ok": passed, "audit": {"ok": chain["ok"], "checked": chain["checked"]}, "steps": steps, "audit_entries": mine,
            "verified": ["the local policy engine allows a harmless call and issues a single-use grant",
                         "a grant cannot be reused for different arguments",
                         "a forbidden command is denied and its simulated side effect did not happen",
                         "a high-impact command is routed to a human",
                         "each decision is in the hash-chained audit log"],
            "not_verified": ["that your AI client routes its tool calls through Provenant (see `provenant status`: "
                             "it shows 'connected' only after real traffic)",
                             "tools or clients that are not wrapped or hooked are not protected",
                             "the policy cannot catch every harmful action; see docs/THREAT_MODEL.md"]}


# --- doctor --------------------------------------------------------------------------------------
def _check(cid: str, status: str, summary: str, fix: str | None = None) -> dict:
    return {"id": cid, "status": status, "summary": summary, **({"fix": fix} if fix else {})}


def _cmd_exists(cmd: list[str]) -> bool:
    exe = cmd[0] if cmd else ""
    return bool(exe) and (Path(exe).exists() or shutil.which(exe) is not None)


def doctor() -> dict:
    cli = _cli()
    win = sys.platform == "win32"
    checks = [_check("python", "ok" if sys.version_info >= (3, 10) else "fail",
                     f"Python {sys.version.split()[0]} at {sys.executable}",
                     None if sys.version_info >= (3, 10) else "install Python 3.10 or newer")]
    import agentshield
    pkg_dir = Path(agentshield.__file__).resolve().parent
    checks.append(_check("package", "ok", f"provenant {cli.VERSION} from {pkg_dir}"))
    on_path = shutil.which("provenant")
    if on_path:
        checks.append(_check("command", "ok", f"`provenant` resolves to {on_path}"))
    else:
        scripts = sysconfig.get_path("scripts", f"{os.name}_user") if "site-packages" in str(pkg_dir) else None
        py = "py" if win else "python3"
        checks.append(_check("command", "warn", "`provenant` is not on PATH in this shell" +
                             (f" (pip put it in {scripts})" if scripts else ""),
                             f"use `{py} -m provenant <command>`, which always works, or rerun the installer "
                             f"({'install.ps1' if win else 'install.sh'}) to add a `provenant` command"))
    pol_file = guard_mod.DEFAULT_GUARD_POLICY
    checks.append(_check("resources", "ok" if Path(pol_file).exists() else "fail", f"built-in policy at {pol_file}",
                         None if Path(pol_file).exists() else "reinstall Provenant: the package is missing its policy file"))
    try:
        g = guard_mod.Guard()
    except Exception as exc:                     # state folder unusable
        checks.append(_check("state", "fail", f"cannot open ~/.provenant ({type(exc).__name__}: {exc})",
                             "check the folder exists and is writable, or set PROVENANT_HOME"))
        return {"ok": False, "checks": checks}
    checks.append(_check("state", "ok", f"state folder {g.store.home} ({g.mode} mode)"))
    checks.append(_check("policy", "fail" if g.policy.load_error else "ok",
                         g.policy.load_error or f"policy {g.policy.version} loaded",
                         "fix the JSON in your policy file, or delete it to use the built-in policy" if g.policy.load_error else None))
    v = g.audit.verify()
    checks.append(_check("audit", "ok" if v["ok"] else "fail",
                         f"audit chain intact ({v['checked']} entries)" if v["ok"] else f"audit chain broken at #{v['first_bad_seq']}",
                         None if v["ok"] else "keep the file for investigation; `provenant audit export` copies it"))
    for name, path in cli.client_configs().items():
        if not path.exists():
            continue
        label = cli.CLIENT_LABELS.get(name, name)
        try:
            servers = cli._servers(cli._load(path))
        except (OSError, ValueError) as exc:
            checks.append(_check(f"client:{name}", "fail", f"{label}: {path} is not valid JSON ({type(exc).__name__})",
                                 f"fix or restore it from a backup next to it ({path.name}.provenant-backup-*)"))
            continue
        wrapped = {n: e for n, e in servers.items() if isinstance(e, dict) and cli.MARK in e}
        broken = [n for n, e in wrapped.items() if not _cmd_exists([e.get("command", "")])]
        if broken:
            checks.append(_check(f"client:{name}", "fail", f"{label}: wrapped servers point at a Python that no longer exists: "
                                 f"{', '.join(broken)}", f"run `provenant unwrap {name}` then `provenant setup`"))
        elif wrapped:
            checks.append(_check(f"client:{name}", "ok", f"{label}: {len(wrapped)}/{len(servers)} MCP servers routed through Provenant"))
        else:
            checks.append(_check(f"client:{name}", "info", f"{label}: config found, nothing routed through Provenant",
                                 "run `provenant setup`" if servers else None))
    cc = cli._claude_code_settings()
    if cli._hook_installed(cc):
        cmds = [h.get("command", "") for grp in cli._load(cc).get("hooks", {}).get("PreToolUse", [])
                for h in grp.get("hooks", []) if cli._is_our_hook(h.get("command", ""))]
        exe = cmds[0].split('"')[1] if cmds and cmds[0].startswith('"') else (cmds[0].split()[0] if cmds else "")
        ok = _cmd_exists([exe])
        checks.append(_check("client:claude-code", "ok" if ok else "fail",
                             "Claude Code hook installed" if ok else f"Claude Code hook points at a missing program ({exe})",
                             None if ok else "run `provenant uninstall claude-code` then `provenant setup`"))
    elif (Path.home() / ".claude").exists() or shutil.which("claude"):
        checks.append(_check("client:claude-code", "info", "Claude Code found, hook not installed", "run `provenant setup`"))
    from . import classifier
    clf, err = classifier.load(g.store.home)
    if err:
        checks.append(_check("model", "fail", f"model.json is invalid: {err}; model assistance is off",
                             "fix ~/.provenant/model.json or delete it (deterministic protection keeps working)"))
    elif clf.enabled:
        d = clf.describe()
        checks.append(_check("model", "ok" if d["api_key_present"] else "warn",
                             f"model assistance on: {d['model']} at {d['endpoint_host']} (sends {d['send']} arguments)",
                             None if d["api_key_present"] else f"set the {d['api_key_env']} environment variable if the endpoint needs a key"))
    else:
        checks.append(_check("model", "info", "model assistance off (deterministic protection only)"))
    return {"ok": not any(c["status"] == "fail" for c in checks), "checks": checks}


# --- rollback ------------------------------------------------------------------------------------
def rollback_plan(clients: list[str] | None = None) -> list[dict]:
    cli = _cli()
    plan = []
    for name, path in cli.client_configs().items():
        if clients and name not in clients or not path.exists():
            continue
        try:
            cfg = cli._load(path)
        except (OSError, ValueError):
            plan.append({"client": name, "path": str(path), "error": "not valid JSON; restore a backup by hand"})
            continue
        names = [n for n, e in cli._servers(cfg).items() if isinstance(e, dict) and isinstance(e.get(cli.MARK), dict)]
        if names:
            plan.append({"client": name, "path": str(path), "restore": names})
    for scope, settings in (("claude-code", cli._claude_code_settings()),
                            ("claude-code-project", Path.cwd() / ".claude" / "settings.json")):
        if (not clients or "claude-code" in clients) and cli._hook_installed(settings):
            plan.append({"client": scope, "path": str(settings), "remove_hook": True})
    return plan


def apply_rollback(plan: list[dict]) -> list[dict]:
    cli = _cli()
    done = []
    for item in plan:
        path = Path(item["path"])
        try:
            if item.get("remove_hook"):
                cli.install_claude_code(path, remove=True)
                ok = not cli._hook_installed(path)
            elif item.get("restore"):
                cfg = cli._load(path)
                cli.unwrap_config(cfg)
                cli._save(path, cfg)
                ok = not any(isinstance(e, dict) and cli.MARK in e for e in cli._servers(cli._load(path)).values())
            else:
                ok = False
        except (OSError, ValueError) as exc:
            item = {**item, "error": f"{type(exc).__name__}: {exc}"}
            ok = False
        done.append({**item, "ok": ok})
    return done


def backups() -> list[str]:
    cli = _cli()
    out = []
    for path in list(cli.client_configs().values()) + [cli._claude_code_settings()]:
        if path.parent.exists():
            out += sorted(str(p) for p in path.parent.glob(path.name + ".provenant-backup-*"))
    return out
