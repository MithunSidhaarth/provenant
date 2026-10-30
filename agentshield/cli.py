"""`provenant`: one command to put Provenant between your agents and their real tools.

    provenant setup                    detect Claude Desktop, Cursor, Windsurf and Claude Code; wrap them all
    provenant wrap <client|path>       route every stdio MCP server in a client config through the proxy
    provenant unwrap <client|path>     restore the original config entries
    provenant install claude-code      add the PreToolUse/PostToolUse/UserPromptSubmit hooks to Claude Code
    provenant uninstall claude-code    remove them again
    provenant status                   what is protected, policy version, audit chain, pending approvals
    provenant pending | approve ID | reject ID | log [-f] | verify | check TOOL ARGS
    provenant policy init              copy the built-in policy to ~/.provenant/policy.json to customise it
    provenant policy test|lint|explain simulate the policy on saved scenarios, find shadowed/overbroad rules
    provenant serve [--workspace DIR]  run provenant-tools: an MCP server whose tools the gateway executes
    provenant call APPROVAL_ID         phone the human (claude-call-me) about one held call
    provenant audit checkpoint|verify|prune|export   external anchoring, retention and export
    provenant config claude-desktop    print an mcpServers snippet for provenant-tools
    provenant proxy -- <cmd...>        run the MCP proxy (what wrapped configs launch)
    provenant hook                     run the Claude Code hook (what Claude Code launches)

Config edits are reversible: the original entry is kept inside the wrapped one and a timestamped backup
of the whole file is written next to it. Standard library only; Windows, macOS and Linux.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path

from . import guard as guard_mod

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


def cmd_wrap(target: str, undo: bool = False, workspace: str | None = None, dry: bool = False) -> int:
    path = _resolve_client(target)
    if not path.exists():
        print(f"{target}: no config at {path}")
        return 1
    cfg = _load(path)
    if undo:
        names = unwrap_config(cfg)
        print(f"{target}: restored {names or 'nothing'}")
    else:
        names, skipped = wrap_config(cfg, workspace)
        print(f"{target}: protected {names or 'nothing new'}" + (f"; skipped {skipped}" if skipped else ""))
    if names and not dry:
        _save(path, cfg)
        print(f"  wrote {path} (backup kept next to it). Restart the client to apply.")
    return 0


# --- Claude Code hooks -------------------------------------------------------------------------------
def _hook_command() -> str:
    return " ".join(f'"{p}"' if " " in p or "\\" in p else p for p in launcher() + ["hook"])


def install_claude_code(settings: Path, remove: bool = False) -> str:
    cfg = _load(settings)
    hooks = cfg.setdefault("hooks", {})
    cmd = _hook_command()
    changed = False
    for event, wants_matcher in HOOK_EVENTS.items():
        groups = hooks.setdefault(event, [])
        mine = [g for g in groups if any("provenant" in h.get("command", "") and h.get("command", "").endswith("hook")
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


# --- status ----------------------------------------------------------------------------------------
def cmd_status() -> int:
    g = guard_mod.Guard()
    print(f"Provenant home   {g.store.home}")
    pol = os.environ.get("PROVENANT_POLICY") or (g.store.home / "policy.json" if (g.store.home / "policy.json").exists()
                                                 else guard_mod.DEFAULT_GUARD_POLICY)
    print(f"Policy           {g.policy.version}  ({pol})" + (f"  LOAD ERROR: {g.policy.load_error}" if g.policy.load_error else ""))
    v = g.audit.verify()
    print(f"Audit log        {v['checked']} entries, chain {'OK' if v['ok'] else 'BROKEN at #' + str(v['first_bad_seq'])}")
    print(f"Pending          {len(g.pending())} call(s) waiting for a human")
    for name, path in client_configs().items():
        if not path.exists():
            continue
        try:
            servers = _servers(_load(path))
        except ValueError:
            print(f"{name:<16} {path} (unreadable JSON)")
            continue
        prot = [n for n, e in servers.items() if isinstance(e, dict) and MARK in e]
        print(f"{name:<16} {len(prot)}/{len(servers)} MCP servers protected  ({path})")
    cc = Path.home() / ".claude" / "settings.json"
    on = cc.exists() and "provenant" in cc.read_text(encoding="utf-8", errors="replace") and " hook" in cc.read_text(encoding="utf-8", errors="replace")
    print(f"{'claude-code':<16} hook {'installed' if on else 'not installed'}  ({cc})")
    return 0


def follow_log() -> int:
    path = guard_mod.Store().home / "audit.jsonl"
    path.touch()
    with path.open(encoding="utf-8") as fh:
        fh.seek(0, os.SEEK_END)
        try:
            while True:
                line = fh.readline()
                if not line:
                    time.sleep(0.3)
                    continue
                e = json.loads(line)
                d = e.get("data", {})
                if e["event"] == "policy_decision":
                    mark = {"ALLOW": "  ok ", "DENY": "BLOCK", "REQUIRE_APPROVAL": " HOLD"}.get(d.get("decision"), "  ?  ")
                    why = "; ".join(d.get("reasons", []))
                    print(f"{e['ts'][11:19]} {mark} {d.get('tool')}" + (f"  <- {why}" if why else ""), flush=True)
                elif e["event"] in ("approval_granted", "approval_rejected", "approval_used", "manifest_withheld",
                                    "manifest_refused", "proxy_start"):
                    print(f"{e['ts'][11:19]}  ...  {e['event']} {json.dumps(d, ensure_ascii=False)[:140]}", flush=True)
                elif e["event"] == "tool_result" and d.get("injection_indicators"):
                    print(f"{e['ts'][11:19]} TAINT {d.get('tool')} output has injection indicators "
                          f"{[f['label'] for f in d['injection_indicators']]}", flush=True)
        except KeyboardInterrupt:
            return 0


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


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "proxy":
        from .mcp_proxy import main as proxy_main
        return proxy_main(rest)
    if cmd == "hook":
        from .cc_hook import main as hook_main
        return hook_main()
    if cmd in ("wrap", "unwrap"):
        if not rest:
            print(f"usage: provenant {cmd} <{'|'.join(client_configs())}|path/to/config.json> [--dry-run]")
            return 2
        ws = rest[rest.index("--workspace") + 1] if "--workspace" in rest else None
        return cmd_wrap(rest[0], undo=cmd == "unwrap", workspace=ws, dry="--dry-run" in rest)
    if cmd in ("install", "uninstall"):
        if not rest or rest[0] != "claude-code":
            print(f"usage: provenant {cmd} claude-code [--project]")
            return 2
        settings = (Path.cwd() / ".claude" / "settings.json") if "--project" in rest else Path.home() / ".claude" / "settings.json"
        print(install_claude_code(settings, remove=cmd == "uninstall"))
        return 0
    if cmd == "setup":
        for name, path in client_configs().items():
            if path.exists() and name != "vscode" and name != "claude-code-project":
                cmd_wrap(name)
        if (Path.home() / ".claude").exists() or shutil.which("claude"):
            print(install_claude_code(Path.home() / ".claude" / "settings.json"))
        print("Done. Watch decisions live with: provenant log -f")
        return 0
    if cmd == "status":
        return cmd_status()
    if cmd == "log" and rest[:1] in (["-f"], ["--follow"]):
        return follow_log()
    if cmd == "serve":
        from .tool_server import main as serve_main
        return serve_main(rest)
    if cmd == "call":
        if not rest:
            print("usage: provenant call APPROVAL_ID")
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
            print(f"{dst} already exists")
            return 1
        shutil.copy2(guard_mod.DEFAULT_GUARD_POLICY, dst)
        print(f"wrote {dst}; edit it to customise the policy (agents cannot: the folder is protected)")
        return 0
    if cmd == "pins" and rest[:1] == ["reset"]:
        pins = guard_mod.Store().home / "pins"
        n = 0
        for p in pins.glob("*.json") if pins.exists() else []:
            if len(rest) < 2 or p.stem == rest[1]:
                p.unlink()
                n += 1
        print(f"cleared {n} pin file(s); tools will be re-pinned on next listing")
        return 0
    return guard_mod.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
