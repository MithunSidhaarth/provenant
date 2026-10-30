"""`provenant`: put a deterministic firewall between your AI agents and their real tools.

Run `provenant` with no arguments for the command list. Everything here is presentation and setup;
the decisions are made by guard.py. Config edits are reversible: the original entry is kept inside the
wrapped one and a timestamped backup of the whole file is written next to it.
Standard library only; Windows, macOS and Linux.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path

from . import guard as guard_mod
from . import ui
from .ui import SYM, bold, cyan, dim, green, red, yellow

try:
    from importlib.metadata import version as _pkg_version
    VERSION = _pkg_version("provenant")
except Exception:
    VERSION = "0.9.0"

CLIENT_LABELS = {"claude-desktop": "Claude Desktop", "cursor": "Cursor", "windsurf": "Windsurf",
                 "antigravity": "Antigravity",
                 "vscode": "VS Code (this folder)", "claude-code-project": "Claude Code (.mcp.json)"}

ROOT = Path(__file__).resolve().parent.parent
MARK = "_provenant_original"
HOOK_EVENTS = {"PreToolUse": True, "PostToolUse": True, "UserPromptSubmit": False}


def launcher() -> list[str]:
    """The command that runs Provenant from any working directory, installed with pip or not."""
    script = ROOT / "provenant.py"
    if script.exists():
        return [sys.executable, str(script)]
    return [sys.executable, "-m", "agentshield.cli"]


def client_configs() -> dict[str, Path]:
    home = Path.home()
    if sys.platform == "win32":
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        desktop = appdata / "Claude" / "claude_desktop_config.json"
    elif sys.platform == "darwin":
        desktop = home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    else:
        desktop = home / ".config" / "Claude" / "claude_desktop_config.json"
    return {"claude-desktop": desktop, "cursor": home / ".cursor" / "mcp.json",
            "windsurf": home / ".codeium" / "windsurf" / "mcp_config.json",
            # Google Antigravity (IDE and CLI) global MCP config, per antigravity.google/docs/mcp
            "antigravity": home / ".gemini" / "config" / "mcp_config.json",
            "vscode": Path.cwd() / ".vscode" / "mcp.json", "claude-code-project": Path.cwd() / ".mcp.json"}


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8").strip()
    return json.loads(text) if text else {}


def _save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, path.with_name(path.name + f".provenant-backup-{time.strftime('%Y%m%d-%H%M%S')}"))
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _servers(cfg: dict) -> dict:
    for key in ("mcpServers", "servers"):          # VS Code uses "servers"
        if isinstance(cfg.get(key), dict):
            return cfg[key]
    return {}


def wrap_config(cfg: dict, workspace: str | None = None) -> tuple[list[str], list[str]]:
    """Rewrite stdio servers in place. Returns (wrapped, skipped-with-reason)."""
    wrapped, skipped = [], []
    for name, entry in _servers(cfg).items():
        if not isinstance(entry, dict):
            continue
        if MARK in entry:
            skipped.append(f"{name}: already protected")
            continue
        if not isinstance(entry.get("command"), str):
            skipped.append(f"{name}: remote ({entry.get('type') or 'url'}) servers are not proxied yet")
            continue
        original = {k: entry[k] for k in ("command", "args") if k in entry}
        args = [str(a) for a in entry.get("args", [])]
        cmd = launcher() + ["proxy", "--name", name] + (["--workspace", workspace] if workspace else []) + \
            ["--", entry["command"]] + args
        entry["command"], entry["args"] = cmd[0], cmd[1:]
        entry[MARK] = original
        wrapped.append(name)
    return wrapped, skipped


def unwrap_config(cfg: dict) -> list[str]:
    restored = []
    for name, entry in _servers(cfg).items():
        if isinstance(entry, dict) and isinstance(entry.get(MARK), dict):
            orig = entry.pop(MARK)
            entry.pop("args", None)
            entry.update(orig)
            restored.append(name)
    return restored


def _resolve_client(target: str) -> Path:
    known = client_configs()
    return known[target] if target in known else Path(target).expanduser()


# --- Claude Code hooks ---------------------------------------------------------------------------
def _hook_command() -> str:
    return " ".join(f'"{p}"' if " " in p or "\\" in p else p for p in launcher() + ["hook"])


def _is_our_hook(cmd: str) -> bool:
    # Source checkouts launch provenant.py, pip installs launch `-m agentshield.cli`.
    return isinstance(cmd, str) and cmd.endswith(" hook") and ("provenant" in cmd or "agentshield" in cmd)


def install_claude_code(settings: Path, remove: bool = False) -> str:
    cfg = _load(settings)
    hooks = cfg.setdefault("hooks", {})
    cmd = _hook_command()
    changed = False
    for event, wants_matcher in HOOK_EVENTS.items():
        groups = hooks.setdefault(event, [])
        mine = [g for g in groups if any(_is_our_hook(h.get("command", ""))
                                         for h in g.get("hooks", []))]
        if remove:
            for g in mine:
                groups.remove(g)
                changed = True
            if not groups:
                hooks.pop(event)
            continue
        if mine:
            continue
        group = {"hooks": [{"type": "command", "command": cmd, "timeout": 30}]}
        if wants_matcher:
            group = {"matcher": "*", **group}
        groups.append(group)
        changed = True
    if not hooks:
        cfg.pop("hooks", None)
    if changed:
        _save(settings, cfg)
    return ("removed from " if remove else "installed in ") + str(settings) if changed else f"no change to {settings}"




# --- status --------------------------------------------------------------------------------------
def _claude_code_settings() -> Path:
    return Path.home() / ".claude" / "settings.json"


def _hook_installed(settings: Path) -> bool:
    try:
        groups = _load(settings).get("hooks", {}).get("PreToolUse", [])
    except (OSError, ValueError):
        return False
    return any(_is_our_hook(h.get("command", ""))
               for g in groups for h in g.get("hooks", []))


def status_dict() -> dict:
    """Machine-readable status, shared by `provenant status` and the dashboard."""
    g = guard_mod.Guard()
    home = g.store.home
    pol = os.environ.get("PROVENANT_POLICY") or (home / "policy.json" if (home / "policy.json").exists()
                                                 else guard_mod.DEFAULT_GUARD_POLICY)
    v = g.audit.verify()
    clients = []
    for name, path in client_configs().items():
        if not path.exists():
            continue
        try:
            servers = _servers(_load(path))
        except (OSError, ValueError):
            clients.append({"name": name, "path": str(path), "protected": [], "unprotected": [], "error": "unreadable JSON"})
            continue
        prot = sorted(n for n, e in servers.items() if isinstance(e, dict) and MARK in e)
        remote = sorted(n for n, e in servers.items() if isinstance(e, dict) and MARK not in e
                        and not isinstance(e.get("command"), str))
        clients.append({"name": name, "path": str(path), "protected": prot, "remote": remote,
                        "unprotected": sorted(n for n in servers if n not in prot and n not in remote)})
    return {"version": VERSION, "home": str(home), "policy_version": g.policy.version, "policy_path": str(pol),
            "policy_error": g.policy.load_error,
            "audit": {"ok": v["ok"], "checked": v["checked"], "first_bad_seq": v["first_bad_seq"]},
            "pending": len(g.pending()), "clients": clients,
            "claude_code_hook": _hook_installed(_claude_code_settings())}


def status_full() -> dict:
    """status_dict() plus the layered protection state (installed / engine / configured / connected / verified)."""
    from . import onboarding
    s = status_dict()
    store = guard_mod.Store()
    s["protection"] = onboarding.protection(s, store.audit.snapshot(), store.home)
    return s


LEVEL_LABELS = {"installed": "Installed", "engine": "Engine ready", "configured": "Configured",
                "connected": "Connected", "verified": "Verified"}


def cmd_status() -> int:
    s = status_full()
    p = s["protection"]
    print(ui.banner(s["version"]))
    print(ui.section("Where you are"))
    lv = p["last_verify"] or {}
    detail = {"installed": "the provenant package runs",
              "engine": "policy loads and the audit chain verifies",
              "configured": "a client config or the Claude Code hook points at Provenant",
              "connected": ("traffic seen from " + ", ".join(p["connected_via"])) if p["connected_via"]
              else "no client tool call has gone through Provenant yet",
              "verified": f"enforcement test passed at {lv.get('at')}" if p["layers"]["verified"]
              else "enforcement test not run against this policy: provenant verify"}
    for name, label in LEVEL_LABELS.items():
        on = p["layers"][name]
        print(ui.row(green(SYM["ok"]) if on else dim(SYM["dot"]), label, detail[name] if on else dim(detail[name]), 18))
    print("\n  " + bold(p["summary"]) + (f"  {dim('Next:')} {cyan(p['next'])}" if p["next"] else ""))
    print(ui.section("Protection"))
    any_client = False
    for c in s["clients"]:
        any_client = True
        total = len(c["protected"]) + len(c["unprotected"])
        remote = dim(f"  (remote, not proxied yet: {', '.join(c['remote'])})") if c.get("remote") else ""
        if c.get("error"):
            print(ui.row(red(SYM["no"]), CLIENT_LABELS.get(c["name"], c["name"]), red(c["error"]), 18))
        elif not total:
            print(ui.row(dim(SYM["dot"]), CLIENT_LABELS.get(c["name"], c["name"]), dim("no local MCP servers") + remote, 18))
        elif not c["unprotected"]:
            print(ui.row(green(SYM["ok"]), CLIENT_LABELS.get(c["name"], c["name"]),
                         f"{total} MCP server{'s' * (total != 1)} protected  " + dim(", ".join(c["protected"])) + remote, 18))
        else:
            print(ui.row(yellow(SYM["warn"]), CLIENT_LABELS.get(c["name"], c["name"]),
                         yellow(f"{len(c['protected'])}/{total} protected  ") + dim("run: provenant setup") + remote, 18))
    print(ui.row(green(SYM["ok"]) if s["claude_code_hook"] else dim(SYM["dot"]), "Claude Code",
                 "hook installed" if s["claude_code_hook"] else dim("hook not installed  (provenant install claude-code)"), 18))
    if not any_client:
        print(ui.row(dim(SYM["dot"]), "MCP clients", dim("none found (Claude Desktop, Cursor, Windsurf)"), 18))
    print(ui.section("Guard"))
    print(ui.row(red(SYM["no"]) if s["policy_error"] else green(SYM["ok"]), "Policy",
                 (red(s["policy_error"]) if s["policy_error"] else s["policy_version"]) + "  " + dim(ui.short_path(s["policy_path"])), 18))
    a = s["audit"]
    print(ui.row(green(SYM["ok"]) if a["ok"] else red(SYM["no"]), "Audit chain",
                 f"{a['checked']} entries, intact" if a["ok"] else red(f"BROKEN at entry #{a['first_bad_seq']}"), 18))
    print(ui.row(yellow(SYM["hold"]) if s["pending"] else green(SYM["ok"]), "Approvals",
                 yellow(f"{s['pending']} waiting  ") + dim("provenant approve") if s["pending"] else "nothing waiting", 18))
    print(ui.row(dim(SYM["dot"]), "State", dim(ui.short_path(s["home"])), 18))
    print()
    return 0 if a["ok"] and not s["policy_error"] else 1


# --- setup ---------------------------------------------------------------------------------------
def _ask(question: str, default: bool = True) -> bool:
    if not sys.stdin or not sys.stdin.isatty():
        return default
    hint = "[Y/n]" if default else "[y/N]"
    try:
        ans = input(f"  {question} {dim(hint)} ").strip().lower()
    except EOFError:
        return default
    return default if not ans else ans in ("y", "yes")


def cmd_setup(yes: bool = False, dry: bool = False, only: list[str] | None = None) -> int:
    print(ui.banner(VERSION))
    print(ui.section("Looking for agents on this machine"))
    plan: list[tuple[str, Path, dict, list[str]]] = []
    for name, path in client_configs().items():
        if name in ("vscode", "claude-code-project") or (only and name not in only):
            continue
        label = CLIENT_LABELS[name]
        if not path.exists():
            print(ui.row(dim(SYM["dot"]), label, dim("not installed"), 18))
            continue
        try:
            cfg = _load(path)
        except (OSError, ValueError):
            print(ui.row(red(SYM["no"]), label, red("config is not valid JSON; skipped"), 18))
            continue
        probe = json.loads(json.dumps(cfg))
        names, skipped = wrap_config(probe)
        already = [n for n, e in _servers(cfg).items() if isinstance(e, dict) and MARK in e]
        if names:
            print(ui.row(cyan(SYM["arrow"]), label, f"will protect {len(names)}: " + bold(", ".join(names)) +
                         (dim(f"  (already: {', '.join(already)})") if already else ""), 18))
            plan.append((label, path, probe, names))
        elif already:
            print(ui.row(green(SYM["ok"]), label, f"{len(already)} already protected " + dim(", ".join(already)), 18))
        else:
            print(ui.row(dim(SYM["dot"]), label, dim("no local MCP servers configured"), 18))
        for s in skipped:
            if "already" not in s:
                print("      " + dim(f"{SYM['dot']} {s}"))
    cc = _claude_code_settings()
    want_hook = (not only or "claude-code" in only) and \
        ((Path.home() / ".claude").exists() or shutil.which("claude")) and not _hook_installed(cc)
    if only and "claude-code" not in only:
        pass
    elif _hook_installed(cc):
        print(ui.row(green(SYM["ok"]), "Claude Code", "hook already installed", 18))
    elif want_hook:
        print(ui.row(cyan(SYM["arrow"]), "Claude Code", "will install the safety hook " + dim(ui.short_path(cc)), 18))
    else:
        print(ui.row(dim(SYM["dot"]), "Claude Code", dim("not installed"), 18))

    if not plan and not want_hook:
        print("\n  " + green("Everything found is already protected.") + "  " + dim("provenant status") + "\n")
        return 0
    if dry:
        print("\n  " + dim("Dry run: nothing changed.") + "\n")
        return 0
    print("\n  " + dim("Each edited file gets a timestamped backup next to it; `provenant rollback` undoes everything."))
    if not yes and not (sys.stdin and sys.stdin.isatty()):
        print("  " + yellow("Not a terminal, so nothing was changed.") + " Re-run with " + cyan("--yes") +
              " to apply this plan non-interactively.\n")
        return 1
    if not yes and not _ask("Apply these changes?"):
        print("  Nothing changed.\n")
        return 1
    print()
    failed, applied = 0, []
    for label, path, cfg, names in plan:
        try:
            _save(path, cfg)
            ok = all(MARK in _servers(_load(path)).get(n, {}) for n in names)   # read back what was written
        except (OSError, ValueError) as exc:
            ok, names = False, [f"{type(exc).__name__}: {exc}"]
        failed += not ok
        applied += [label] if ok else []
        print(ui.row(green(SYM["ok"]) if ok else red(SYM["no"]), label,
                     f"protected {', '.join(names)}" if ok else red(f"failed: {', '.join(names)}"), 18))
    if want_hook:
        try:
            install_claude_code(cc)
            ok = _hook_installed(cc)
        except (OSError, ValueError):
            ok = False
        failed += not ok
        print(ui.row(green(SYM["ok"]) if ok else red(SYM["no"]), "Claude Code", "hook installed" if ok else red("hook install failed"), 18))
    print(ui.section("Next"))
    if applied:
        print(f"  1. Restart {', '.join(applied)} so it launches its tools through Provenant.")
    print(f"  {2 if applied else 1}. Prove enforcement safely:      {cyan('provenant verify')}")
    print(f"  {3 if applied else 2}. See what is protected:        {cyan('provenant status')}")
    print(f"  {dim('Undo all of this any time:      provenant rollback')}")
    print()
    return 1 if failed else 0


def cmd_wrap(target: str, undo: bool = False, workspace: str | None = None, dry: bool = False) -> int:
    path = _resolve_client(target)
    label = CLIENT_LABELS.get(target, target)
    if not path.exists():
        print(ui.row(red(SYM["no"]), label, f"no config at {path}", 18))
        return 1
    cfg = _load(path)
    if undo:
        names = unwrap_config(cfg)
        print(ui.row(green(SYM["ok"]), label, f"restored {', '.join(names)}" if names else dim("nothing to restore"), 18))
    else:
        names, skipped = wrap_config(cfg, workspace)
        print(ui.row(green(SYM["ok"]), label, f"protected {', '.join(names)}" if names else dim("nothing new to protect"), 18))
        for s in skipped:
            print("      " + dim(f"{SYM['dot']} {s}"))
    if names and not dry:
        _save(path, cfg)
        print("      " + dim(f"wrote {path} (backup kept next to it). Restart the client to apply."))
    return 0


# --- audit feed ----------------------------------------------------------------------------------
def _mask(text: str) -> str:
    for rx, name in getattr(guard_mod, "SECRET_PATTERNS_C", []):
        text = rx.sub(f"[{name}]", text)
    return text


def _summary(tool: str, args) -> str:
    if isinstance(args, dict):
        for k in ("command", "cmd", "file_path", "path", "url", "to", "pattern", "query", "notebook_path"):
            if isinstance(args.get(k), str) and args[k]:
                return _mask(args[k])
        return _mask(json.dumps(args, ensure_ascii=False))
    return _mask(str(args))


def _short_tool(tool: str) -> str:
    if isinstance(tool, str) and tool.startswith("mcp__"):
        parts = tool.split("__")
        return f"{parts[1]}.{parts[-1]}" if len(parts) >= 3 else tool
    return str(tool)


class _Feed:
    """Pairs each tool_request with its policy_decision so a line can show what was asked and why."""

    def __init__(self) -> None:
        self.requests: dict[str, dict] = {}
        self.holds: dict[str, str] = {}

    def render(self, e: dict) -> str | None:
        d = e.get("data") if isinstance(e.get("data"), dict) else {}
        t = e.get("ts", "")[11:19]
        ev = e.get("event")
        w = ui.width()
        if ev == "tool_request":
            self.requests[d.get("call_id", "")] = d
            return None
        if ev == "policy_decision":
            req = self.requests.pop(d.get("call_id", ""), {})
            tool = _short_tool(d.get("tool"))
            what = ui.clip(_summary(d.get("tool"), req.get("args")), max(20, w - 40 - len(tool)))
            line = f"  {dim(t)} {ui.badge(d.get('decision', '?'))} {bold(tool)}  {what}"
            reasons = d.get("reasons") or []
            if reasons and d.get("decision") != "ALLOW":
                col = red if d.get("decision") == "DENY" else yellow
                line += "\n" + " " * 20 + col(SYM["bar"] + " " + ui.clip("; ".join(reasons), w - 24))
            return line
        if ev == "approval_requested":
            return " " * 20 + yellow(f"{SYM['bar']} held as {d.get('approval_id')}  ") + dim(f"approve: provenant approve {d.get('approval_id')}")
        if ev in ("approval_granted", "approval_rejected"):
            ok = ev == "approval_granted"
            return f"  {dim(t)} {(green if ok else red)(('  ' + SYM['ok'] + ' approved' if ok else '  ' + SYM['no'] + ' rejected'))} " \
                   f"{d.get('approval_id')} by {str(d.get('approver', '')).removeprefix('human:')}"
        if ev == "approval_used":
            return " " * 20 + green(f"{SYM['bar']} ran once under {d.get('approval_id')}")
        if ev == "tool_result" and d.get("injection_indicators"):
            labels = ", ".join(sorted({f.get('label', '?') for f in d["injection_indicators"]}))
            return f"  {dim(t)} {ui.on_yellow(' TAINT ') if ui.COLOR else '[TAINT]'} {bold(_short_tool(d.get('tool')))}  " \
                   + yellow(ui.clip(f"injection in output ({labels}); side effects now need a human", ui.width() - 40))
        if ev in ("manifest_withheld", "manifest_refused"):
            what = ", ".join(sorted(d.get("withheld", {}))) or d.get("tool", "")
            return f"  {dim(t)} {ui.badge('DENY')} {bold('manifest')}  tool definition changed or poisoned: {what}"
        if ev == "proxy_start":
            return f"  {dim(t)} {dim('  ' + SYM['arrow'] + ' proxy up for')} {bold(str(d.get('server')))}"
        return None


def cmd_log(n: int = 25, follow: bool = False) -> int:
    store = guard_mod.Store()
    feed = _Feed()
    print(ui.banner(VERSION, "live tool-call feed" if follow else "recent tool calls") + "\n")
    entries = store.audit.snapshot()
    shown = 0
    for e in entries[-max(n * 3, n):]:
        line = feed.render(e)
        if line:
            print(line)
            shown += 1
    if not shown and not follow:
        print("  " + dim("No tool calls yet. Use an agent, or try: provenant check Bash '{\"command\":\"ls\"}'"))
    if not follow:
        print()
        return 0
    print("  " + dim(f"watching {store.home / 'audit.jsonl'}  (Ctrl+C to stop)"), flush=True)
    path = store.home / "audit.jsonl"
    path.touch()
    with path.open(encoding="utf-8") as fh:
        fh.seek(0, os.SEEK_END)
        try:
            while True:
                line = fh.readline()
                if not line or not line.endswith("\n"):
                    if line:
                        fh.seek(fh.tell() - len(line.encode("utf-8")))
                    time.sleep(0.25)
                    continue
                try:
                    out = feed.render(json.loads(line))
                except ValueError:
                    continue
                if out:
                    print(out, flush=True)
        except KeyboardInterrupt:
            print()
            return 0


# --- approvals -----------------------------------------------------------------------------------
def _print_pending(rows: list[dict]) -> None:
    now = time.time()
    for i, p in enumerate(rows, 1):
        mins = max(0, int((p["expires_at"] - now) // 60))
        meta = f"from {p.get('source', '?')}, expires in {mins} min"
        print(f"\n  {yellow(SYM['hold'])} {bold(p['approval_id'])}  {dim(meta)}")
        print(f"      {bold(_short_tool(p['tool']))}  {ui.clip(_summary(p['tool'], p['args']), ui.width() - 30)}")
        for r in p.get("reasons", []):
            print("      " + dim(f"{SYM['dot']} {ui.clip(r, ui.width() - 10)}"))


def cmd_pending() -> int:
    rows = guard_mod.Guard().pending()
    print(ui.banner(VERSION, "calls waiting for a human"))
    if not rows:
        print("  " + green(SYM["ok"]) + " Nothing is waiting for approval.\n")
        return 0
    _print_pending(rows)
    print("\n  " + dim("provenant approve <id>   or   provenant approve   (walks through each one)") + "\n")
    return 0


def cmd_decide(approve: bool, approval_id: str | None, who: str | None) -> int:
    import getpass
    if not sys.stdin.isatty():
        # An agent's shell tool has no terminal; a person typing does. The policy also DENYs agents running this.
        print(red(f"  {SYM['no']} refused: approvals must be typed by a person at a terminal"))
        return 2
    g = guard_mod.Guard()
    approver = "human:" + (who or getpass.getuser())
    rows = g.pending()
    if approval_id:
        targets = [p for p in rows if p["approval_id"] == approval_id] or [{"approval_id": approval_id}]
        ask_each = False
    else:
        if not rows:
            print("  " + green(SYM["ok"]) + " Nothing is waiting for approval.")
            return 0
        targets, ask_each = rows, True
    rc = 0
    for p in targets:
        if ask_each:
            _print_pending([p])
            if not _ask("Approve this call?" if approve else "Reject this call?", default=False):
                print("      " + dim("skipped"))
                continue
        r = g.decide(p["approval_id"], approver, approve)
        if r["ok"]:
            msg = (f"approved {p['approval_id']}. The agent may now retry that exact call once."
                   if approve else f"rejected {p['approval_id']}.")
            print("      " + (green if approve else yellow)(SYM["ok"] + " " + msg))
        else:
            print("      " + red(f"{SYM['no']} {p['approval_id']}: {r['reason']}"))
            rc = 1
    print()
    return rc


# --- check / verify ------------------------------------------------------------------------------
def cmd_check(tool: str, args_json: str, workspace: str) -> int:
    try:
        args = json.loads(args_json)
    except ValueError:
        print(red(f"  {SYM['no']} arguments must be JSON, e.g. '{{\"command\": \"ls\"}}'"))
        return 2
    g = guard_mod.Guard()
    res = g.policy.evaluate(guard_mod.GuardCall(tool, args, "cli-check", workspace, "cli"), g.store.load_session("cli-check"))
    print(f"\n  {ui.badge(res.decision.value)} {bold(tool)}  {ui.clip(_summary(tool, args), ui.width() - 30)}")
    for f in res.findings:
        if f.decision.value != "ALLOW":
            col = red if f.decision.value == "DENY" else yellow
            print("          " + col(f"{SYM['bar']} {f.rule}: ") + f.reason)
    print("\n  " + dim("Dry run: nothing was executed or logged.") + "\n")
    return 0


def cmd_verify(as_json: bool = False) -> int:
    """The safe enforcement self-test (onboarding.self_test), then which integrations are actually live."""
    from . import onboarding
    r = onboarding.self_test()
    s = status_full()
    r["protection"] = s["protection"]
    if as_json:
        print(json.dumps(r, indent=2))
        return 0 if r["passed"] else 1
    print(ui.banner(VERSION))
    print(ui.section("Enforcement test  " + dim("(harmless, local, simulated; nothing destructive runs)")))
    for st in r["steps"]:
        mark = green(SYM["ok"]) if st["passed"] else red(SYM["no"])
        print(f"  {mark} {st['action']}")
        print("      " + dim(f"expected {st['expected']}, got ") + (st["got"] if st["passed"] else red(st["got"])) +
              (dim("  " + "; ".join(st["reasons"])) if st.get("reasons") else ""))
    print(ui.section("Audit entries written"))
    for e in r["audit_entries"]:
        print(f"    #{e['seq']:<6} {ui.badge(e['decision'])} {e['tool']}  " + dim(e["hash"]))
    print()
    if r["passed"]:
        print("  " + green(bold("Enforcement verified.")) + " The policy engine on this machine blocks, holds and records as expected.")
    else:
        print("  " + red(bold("Enforcement test FAILED.")) + " Run " + cyan("provenant doctor") + ".")
    p = r["protection"]
    print("  " + dim("Not proven by this test: ") + p["summary"] + (f"  {dim('Next:')} {cyan(p['next'])}" if p["next"] else ""))
    print()
    return 0 if r["passed"] else 1


def cmd_doctor(as_json: bool = False) -> int:
    from . import onboarding
    r = onboarding.doctor()
    if as_json:
        print(json.dumps(r, indent=2))
        return 0 if r["ok"] else 1
    print(ui.banner(VERSION))
    icons = {"ok": green(SYM["ok"]), "warn": yellow(SYM["warn"]), "fail": red(SYM["no"]), "info": dim(SYM["dot"])}
    for c in r["checks"]:
        print(f"  {icons[c['status']]} {c['summary']}")
        if c.get("fix"):
            print("      " + dim("fix: ") + c["fix"])
    print("\n  " + (green("No problems found.") if r["ok"] else red("Problems found; see the fixes above.")) + "\n")
    return 0 if r["ok"] else 1


def cmd_rollback(yes: bool, dry: bool, only: list[str] | None, as_json: bool = False) -> int:
    from . import onboarding
    plan = onboarding.rollback_plan(only)
    if not as_json:
        print(ui.banner(VERSION))
        print(ui.section("Undo Provenant's client changes"))
        for item in plan:
            label = CLIENT_LABELS.get(item["client"], item["client"])
            what = item.get("error") or ("remove the safety hook" if item.get("remove_hook") else f"restore {', '.join(item['restore'])}")
            print(ui.row(cyan(SYM["arrow"]) if not item.get("error") else red(SYM["no"]), label, what + "  " + dim(ui.short_path(item["path"])), 18))
    actionable = [i for i in plan if not i.get("error")]
    if not actionable:
        print(json.dumps({"plan": plan, "done": []}) if as_json else "  " + green("Nothing to undo.") + "\n")
        return 0
    if dry or (not yes and not _ask("Restore these configurations?", default=False)):
        print(json.dumps({"plan": plan, "done": []}) if as_json else "  Nothing changed.\n")
        return 0 if dry else 1
    done = onboarding.apply_rollback(actionable)
    if as_json:
        print(json.dumps({"plan": plan, "done": done}))
    else:
        for d in done:
            print(ui.row(green(SYM["ok"]) if d["ok"] else red(SYM["no"]), CLIENT_LABELS.get(d["client"], d["client"]),
                         "restored" if d["ok"] else red(d.get("error", "failed")), 18))
        print("\n  " + dim("Backups of every earlier version stay next to each file. Restart your clients to apply.") + "\n")
    return 0 if all(d["ok"] for d in done) else 1


def cmd_model(rest: list[str]) -> int:
    from . import classifier
    home = guard_mod.Store().home
    clf, err = classifier.load(home)
    sub = rest[0] if rest else "status"
    if sub == "status":
        d = {"config": str(classifier.config_path(home)), "error": err, **clf.describe()}
        d["escalation_enabled_by_policy"] = isinstance(guard_mod.GuardPolicy.from_file().config.get("model_assist"), dict)
        print(json.dumps(d, indent=2))
        return 1 if err else 0
    if sub == "test":
        if not clf.enabled:
            print(json.dumps({"ok": False, "error": err or "model assistance is not enabled in " + str(classifier.config_path(home))}))
            return 1
        payload = classifier.minimal_payload("Bash", {"command": "ls -la"}, "shell", clf.send, clf.max_chars)
        try:
            a = clf.classify(payload)
            print(json.dumps({"ok": True, "sent": payload, "advice": a.to_dict()}, indent=2))
            return 0
        except classifier.ClassifierError as exc:
            print(json.dumps({"ok": False, "error": str(exc)}))
            return 1
    print("  usage: provenant model status|test")
    return 2


def cmd_verify_audit(as_json: bool = False) -> int:
    v = guard_mod.Store().audit.verify()
    if as_json:
        print(json.dumps(v))
        return 0 if v["ok"] else 1
    if v["ok"]:
        print(f"\n  {green(SYM['ok'])} Audit chain intact: {v['checked']} entries.  head {dim(str(v.get('head', ''))[:16])}\n")
        return 0
    print(f"\n  {red(SYM['no'])} Audit chain BROKEN at entry #{v['first_bad_seq']}: {v['problem']}\n")
    return 1


# --- v8 commands (serve, call, audit, config, policy test/lint/explain) ---------------------------
def cmd_audit(rest: list[str]) -> int:
    from . import anchor
    g = guard_mod.Guard()
    sub = rest[0] if rest else "verify"
    anchor_dir = os.environ.get("PROVENANT_ANCHOR_DIR")
    if "--anchor" in rest:
        anchor_dir = rest[rest.index("--anchor") + 1]
    if sub == "checkpoint":
        if not anchor_dir:
            print("set --anchor DIR (or PROVENANT_ANCHOR_DIR) to a location outside ~/.provenant you control separately")
            return 2
        r = anchor.checkpoint(g, anchor_dir)
    elif sub == "verify":
        r = anchor.verify_against(g, anchor_dir) if anchor_dir else g.audit.verify()
    elif sub == "prune":
        if "--before" not in rest or "--archive" not in rest:
            print("usage: provenant audit prune --before SEQ --archive FILE")
            return 2
        r = anchor.prune(g, int(rest[rest.index("--before") + 1]), rest[rest.index("--archive") + 1])
    elif sub == "export":
        r = anchor.export(g, rest[rest.index("--out") + 1] if "--out" in rest else "provenant-audit-export.json")
    else:
        print("usage: provenant audit checkpoint|verify|prune|export")
        return 2
    print(json.dumps(r, indent=1))
    return 0 if r.get("ok") else 1


def cmd_config(rest: list[str]) -> int:
    """A copyable MCP client entry for provenant-tools, built from this install's real paths."""
    ws = rest[rest.index("--workspace") + 1] if "--workspace" in rest else os.getcwd()
    cmd = launcher() + ["serve", "--workspace", ws]
    print(json.dumps({"mcpServers": {"provenant": {"command": cmd[0], "args": cmd[1:]}}}, indent=2))
    return 0


# --- entry point ---------------------------------------------------------------------------------
def _help() -> str:
    c = lambda s: cyan(f"{s:<48}")
    return ui.banner(VERSION) + "\n".join([
        ui.section("Get protected"),
        f"    {c('provenant setup')}find your AI clients, show the plan, ask, then protect them",
        f"    {c('provenant verify')}safe enforcement test: allow, block, hold, audit",
        f"    {c('provenant status [--json]')}installed / configured / connected / verified",
        f"    {c('provenant doctor [--json]')}diagnose Python, PATH, configs, policy, audit, model",
        f"    {c('provenant rollback')}undo every client change Provenant made",
        ui.section("Watch and decide"),
        f"    {c('provenant log -f')}live feed of every tool call: OK / BLOCK / HOLD",
        f"    {c('provenant pending')}calls waiting for a human",
        f"    {c('provenant approve [id]')}let one held call run once (asks if no id)",
        f"    {c('provenant reject [id]')}refuse a held call",
        f"    {c('provenant check TOOL JSON')}dry-run a call through the policy",
        f"    {c('provenant audit verify')}check the audit log has not been tampered with",
        ui.section("Fine control"),
        f"    {c('provenant wrap|unwrap CLIENT')}claude-desktop, cursor, windsurf, vscode, or a path",
        f"    {c('provenant install|uninstall claude-code')}the Claude Code safety hook (--project for this repo)",
        f"    {c('provenant policy init')}copy the policy to ~/.provenant to customise it",
        f"    {c('provenant policy test|lint|explain')}simulate the policy, find shadowed or overbroad rules",
        f"    {c('provenant audit checkpoint|verify|prune|export')}external anchoring, retention and export",
        ui.section("Gateway mode"),
        f"    {c('provenant serve [--workspace DIR]')}provenant-tools: an MCP server the gateway executes",
        f"    {c('provenant config claude-desktop')}print an mcpServers snippet for provenant-tools",
        f"    {c('provenant call APPROVAL_ID')}phone the human about one held call",
        f"    {c('provenant pins reset [server]')}re-approve tool definitions after an upgrade",
        f"    {c('provenant model status|test')}optional model-assisted risk labels (off by default)",
        f"    {c('provenant mail setup|status|test')}scan MCP email results; configure Bolna phone alerts",
        f"    {c('provenant mail enable|disable')}turn high-risk email phone alerts on or off",
        "",
        "  " + dim("Docs: https://github.com/MithunSidhaarth/provenant/blob/main/docs/REAL_GUARD.md"),
        ""])


def _opt(rest: list[str], name: str, default=None):
    return rest[rest.index(name) + 1] if name in rest and rest.index(name) + 1 < len(rest) else default


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(_help())
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd in ("-V", "--version", "version"):
        print(f"provenant {VERSION}")
        return 0
    if cmd == "proxy":
        from .mcp_proxy import main as proxy_main
        return proxy_main(rest)
    if cmd == "hook":
        from .cc_hook import main as hook_main
        return hook_main()
    only = [rest[i + 1] for i, a in enumerate(rest[:-1]) if a == "--client"] or None
    if cmd == "setup":
        return cmd_setup(yes="--yes" in rest or "-y" in rest, dry="--dry-run" in rest, only=only)
    if cmd == "status":
        if "--json" in rest:
            print(json.dumps(status_full(), indent=2))
            return 0
        return cmd_status()
    if cmd == "doctor":
        return cmd_doctor("--json" in rest)
    if cmd == "rollback":
        return cmd_rollback(yes="--yes" in rest or "-y" in rest, dry="--dry-run" in rest, only=only, as_json="--json" in rest)
    if cmd == "model":
        return cmd_model(rest)
    if cmd == "mail":
        from . import mail_security
        return mail_security.main(rest)
    if cmd == "log":
        return cmd_log(int(_opt(rest, "-n", 25)), follow="-f" in rest or "--follow" in rest)
    if cmd == "pending":
        return cmd_pending()
    if cmd in ("approve", "reject"):
        ids = [a for a in rest if not a.startswith("-") and a != _opt(rest, "--as")]
        return cmd_decide(cmd == "approve", ids[0] if ids else None, _opt(rest, "--as"))
    if cmd == "check":
        pos = [a for a in rest if a != "--workspace" and a != _opt(rest, "--workspace")]
        if not pos:
            print("  usage: provenant check TOOL '{\"arg\": \"value\"}' [--workspace DIR]")
            return 2
        return cmd_check(pos[0], pos[1] if len(pos) > 1 else "{}", _opt(rest, "--workspace", os.getcwd()))
    if cmd == "verify":
        if "--audit-only" in rest:
            return cmd_verify_audit("--json" in rest)
        return cmd_verify("--json" in rest)
    if cmd in ("wrap", "unwrap"):
        if not rest:
            print(f"  usage: provenant {cmd} <{'|'.join(client_configs())}|path/to/config.json> [--dry-run]")
            return 2
        return cmd_wrap(rest[0], undo=cmd == "unwrap", workspace=_opt(rest, "--workspace"), dry="--dry-run" in rest)
    if cmd in ("install", "uninstall"):
        if not rest or rest[0] != "claude-code":
            print(f"  usage: provenant {cmd} claude-code [--project]")
            return 2
        settings = (Path.cwd() / ".claude" / "settings.json") if "--project" in rest else _claude_code_settings()
        msg = install_claude_code(settings, remove=cmd == "uninstall")
        print("  " + (green(SYM["ok"]) + " " if not msg.startswith("no change") else dim(SYM["dot"]) + " ") + msg)
        return 0
    if cmd == "serve":
        from .tool_server import main as serve_main
        return serve_main(rest)
    if cmd == "call":
        if not rest:
            print("  usage: provenant call APPROVAL_ID")
            return 2
        from .voice import phone_approve
        r = phone_approve(guard_mod.Guard(), rest[0])
        print(json.dumps(r))
        return 0 if r.get("approved") else 1
    if cmd == "audit":
        return cmd_audit(rest)
    if cmd == "config":
        return cmd_config(rest)
    if cmd == "policy" and rest[:1] in (["test"], ["lint"], ["explain"]):
        from .policysim import main as sim_main
        return sim_main(rest)
    if cmd == "policy" and rest[:1] == ["init"]:
        dst = guard_mod.Store().home / "policy.json"
        if dst.exists():
            print(f"  {dim(SYM['dot'])} {dst} already exists")
            return 1
        shutil.copy2(guard_mod.DEFAULT_GUARD_POLICY, dst)
        print(f"  {green(SYM['ok'])} wrote {dst}\n    edit it to customise the policy (agents cannot: that folder is protected)")
        return 0
    if cmd == "pins" and rest[:1] == ["reset"]:
        pins = guard_mod.Store().home / "pins"
        n = 0
        for p in pins.glob("*.json") if pins.exists() else []:
            if len(rest) < 2 or p.stem == rest[1]:
                p.unlink()
                n += 1
        print(f"  {green(SYM['ok'])} cleared {n} pin file(s); tools are re-pinned on their next listing")
        return 0
    print(f"  {red(SYM['no'])} unknown command '{cmd}'. Run {cyan('provenant')} for the list.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
