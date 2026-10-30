"""Provenant MCP proxy: a real policy enforcement point in front of any stdio MCP server.

    MCP client (Claude Desktop, Cursor, VS Code, Claude Code, any agent)
        │  JSON-RPC over stdio, one message per line
        ▼
    mcp_proxy ──▶ Guard.check (deterministic policy) ──▶ ALLOW: forwarded to the real server
        │                                              ├─ REQUIRE_APPROVAL: held for a human, nothing forwarded
        │                                              └─ DENY: answered by the proxy, nothing forwarded
        ▼
    real MCP server (launched by the proxy as a child process)

Everything else (initialize, resources, prompts, notifications, server-to-client requests) passes
through unchanged. On top of the per-call policy the proxy:

* pins every tool definition the server advertises (HMAC over name, description and schema) the first
  time it sees it, refusing definitions whose description carries an injection. Later lists and calls are
  checked against the pin, so a server that changes a tool after approval ("rug pull") has that tool
  withheld and its calls refused. Pins persist in PROVENANT_HOME/pins/<name>.json;
* scans every tool result as untrusted content: destinations that appear only in it are tainted, and
  injection indicators make later side effects need a human.

Run:  python -m agentshield.mcp_proxy --name filesystem -- npx -y @modelcontextprotocol/server-filesystem ~/work
Usually you do not type this: `provenant wrap` rewrites a client's MCP config to launch servers through it.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import threading

from .detectors import scan_injection
from .guard import APPROVE, DENY, Guard, GuardCall
from .models import canonical_json, new_id


class Pins:
    def __init__(self, guard: Guard, name: str) -> None:
        self.key = guard.store.key
        self.path = guard.store.home / "pins" / (re.sub(r"[^A-Za-z0-9_.\-]", "_", name) + ".json")
        self.path.parent.mkdir(exist_ok=True)
        try:
            self.pins: dict = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.pins = {}
        self.withheld: dict[str, str] = {}

    def sign(self, d: dict) -> str:
        body = {"name": d.get("name"), "description": d.get("description", ""), "inputSchema": d.get("inputSchema", {})}
        return hmac.new(self.key, canonical_json(body).encode(), hashlib.sha256).hexdigest()

    def review(self, tools: list) -> tuple[list, dict]:
        """Split an advertised tool list into (allowed, withheld-with-reasons). Pins new clean tools."""
        ok, withheld, changed = [], {}, False
        for d in tools:
            if not isinstance(d, dict) or not isinstance(d.get("name"), str):
                continue
            name, sig = d["name"], self.sign(d)
            pinned = self.pins.get(name)
            if pinned is None:
                hits = scan_injection(str(d.get("description", "")) + " " + json.dumps(d.get("inputSchema", {})))
                if hits:
                    withheld[name] = "description contains injection indicators: " + ", ".join(h["label"] for h in hits)
                    continue
                self.pins[name] = sig
                changed = True
                ok.append(d)
            elif hmac.compare_digest(pinned, sig):
                ok.append(d)
            else:
                withheld[name] = ("tool definition changed since it was first approved (signature mismatch); "
                                  "a human can re-approve with `provenant pins reset`")
        if changed:
            self.path.write_text(json.dumps(self.pins, indent=1), encoding="utf-8")
        self.withheld = withheld
        return ok, withheld


class MCPProxy:
    def __init__(self, upstream_cmd: list[str], name: str, workspace: str, task: str = "",
                 guard: Guard | None = None, out=None, inp=None) -> None:
        self.guard = guard or Guard()
        self.name = name
        self.workspace = workspace
        self.session_id = f"mcp:{name}:{new_id('s')}"
        self.pins = Pins(self.guard, name)
        self.out = out or sys.stdout
        self.inp = inp or sys.stdin
        self._lock = threading.Lock()
        self._pending: dict = {}             # client request id -> ("list" | "call", tool)
        exe = shutil.which(upstream_cmd[0]) or upstream_cmd[0]    # resolves npx.cmd etc. on Windows
        self.proc = subprocess.Popen([exe] + upstream_cmd[1:], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=None, text=True, encoding="utf-8", bufsize=1)
        self.guard.audit.append("proxy_start", self.session_id, {"server": name, "command": upstream_cmd,
                                                                 "workspace": workspace,
                                                                 "policy_version": self.guard.policy.version})
        if task:
            self.guard.note_user_text(self.session_id, task, "proxy --task")

    # --- plumbing ------------------------------------------------------------------------------
    def _send_client(self, msg: dict) -> None:
        with self._lock:
            self.out.write(json.dumps(msg, ensure_ascii=False) + "\n")
            self.out.flush()

    def _send_upstream(self, msg: dict) -> None:
        self.proc.stdin.write(json.dumps(msg, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()

    def _qualified(self, tool: str) -> str:
        return f"mcp__{self.name}__{tool}"

    # --- client -> server ----------------------------------------------------------------------
    def on_client(self, msg: dict) -> None:
        method, mid = msg.get("method"), msg.get("id")
        if method == "tools/list" and mid is not None:
            self._pending[_key(mid)] = ("list", None)
        elif method == "tools/call" and mid is not None:
            if not self._gate_call(msg):
                return
        self._send_upstream(msg)

    def _gate_call(self, msg: dict) -> bool:
        mid, params = msg.get("id"), msg.get("params") or {}
        name, args = params.get("name"), params.get("arguments", {})
        try:
            if not isinstance(name, str):
                raise ValueError("tool name missing")
            if name in self.pins.withheld:
                reason = self.pins.withheld[name]
                self.guard.audit.append("manifest_refused", self.session_id, {"tool": name, "reason": reason})
                self._refuse(mid, "DENY: Provenant blocked this call. " + reason, "DENY")
                return False
            v = self.guard.check(GuardCall(self._qualified(name), args if args is not None else {},
                                           self.session_id, self.workspace, "mcp"), hold=True)
        except Exception as exc:            # fail closed
            self._refuse(mid, f"DENY: Provenant could not evaluate this call ({type(exc).__name__}); failing closed", "DENY")
            return False
        if v.decision in (DENY, APPROVE):
            self._refuse(mid, v.message(), v.decision.value, v.approval_id)
            _notify(f"[provenant] {v.decision.value} {self.name}.{name}: {'; '.join(v.reasons)[:200]}")
            return False
        self._pending[_key(mid)] = ("call", name)
        return True

    def _refuse(self, mid, text: str, decision: str, approval_id: str | None = None) -> None:
        self._send_client({"jsonrpc": "2.0", "id": mid,
                           "result": {"isError": True, "content": [{"type": "text", "text": text}],
                                      "_meta": {"provenant": {"decision": decision, "approval_id": approval_id}}}})

    # --- server -> client ----------------------------------------------------------------------
    def on_upstream(self, msg: dict) -> None:
        if "method" not in msg and "id" in msg:
            kind = self._pending.pop(_key(msg["id"]), None)
            if kind and kind[0] == "list" and isinstance(msg.get("result"), dict):
                tools, withheld = self.pins.review(msg["result"].get("tools") or [])
                msg["result"]["tools"] = tools
                if withheld:
                    self.guard.audit.append("manifest_withheld", self.session_id, {"withheld": withheld})
                    _notify(f"[provenant] withheld tools from {self.name}: {sorted(withheld)}")
            elif kind and kind[0] == "call":
                try:
                    flags = self.guard.ingest_output(self.session_id, self._qualified(kind[1]), msg.get("result"))
                    if flags:
                        _notify(f"[provenant] injection indicators in {self.name}.{kind[1]} output: "
                                f"{[f['label'] for f in flags]}")
                except Exception:
                    pass                    # logging problems never block a result already allowed
        self._send_client(msg)

    # --- loops ---------------------------------------------------------------------------------
    def _pump_upstream(self) -> None:
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue                    # servers must not print non-protocol text on stdout
            if isinstance(msg, dict):
                self.on_upstream(msg)
            elif isinstance(msg, list):     # JSON-RPC batch
                for m in msg:
                    if isinstance(m, dict):
                        self.on_upstream(m)

    def run(self) -> int:
        t = threading.Thread(target=self._pump_upstream, daemon=True)
        t.start()
        try:
            for line in self.inp:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except ValueError:
                    self._send_client({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
                    continue
                for m in (msg if isinstance(msg, list) else [msg]):
                    if isinstance(m, dict):
                        try:
                            self.on_client(m)
                        except (BrokenPipeError, OSError):
                            return 1
        finally:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            t.join(timeout=2)
            self.guard.audit.append("proxy_stop", self.session_id, {"server": self.name})
        return 0


def _key(mid) -> str:
    return json.dumps(mid)


def _notify(text: str) -> None:
    # stderr is the MCP client's log channel; stdout is reserved for protocol messages.
    try:
        print(text, file=sys.stderr, flush=True)
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--" not in argv:
        print("usage: python -m agentshield.mcp_proxy [--name NAME] [--workspace DIR] [--task TEXT] -- <server command...>",
              file=sys.stderr)
        return 2
    i = argv.index("--")
    ap = argparse.ArgumentParser(prog="provenant proxy")
    ap.add_argument("--name", default=None)
    ap.add_argument("--workspace", default=os.environ.get("PROVENANT_WORKSPACE", os.getcwd()))
    ap.add_argument("--task", default=os.environ.get("PROVENANT_USER_TASK", ""))
    ns = ap.parse_args(argv[:i])
    cmd = argv[i + 1:]
    if not cmd:
        print("no upstream server command after --", file=sys.stderr)
        return 2
    for stream in (sys.stdin, sys.stdout):     # Windows consoles default to a legacy code page and \r\n
        try:
            stream.reconfigure(encoding="utf-8", newline="\n") if stream is sys.stdout else stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    name = ns.name or re.sub(r"[^A-Za-z0-9_\-]", "_", os.path.basename(cmd[-1]) or "server")
    return MCPProxy(cmd, name, ns.workspace, ns.task).run()


if __name__ == "__main__":
    raise SystemExit(main())
