"""Provenant MCP proxy: a real policy enforcement point in front of any stdio MCP server.

    MCP client (Claude Desktop, Cursor, VS Code, Claude Code, any agent)
        │  JSON-RPC over stdio, one message per line
        ▼
    mcp_proxy ──▶ Guard.check (deterministic policy) ──▶ ALLOW: forwarded to the real server
        │                                              ├─ REQUIRE_APPROVAL: held for a human, nothing forwarded
        │                                              └─ DENY: answered by the proxy, nothing forwarded
        ▼
    real MCP server (launched by the proxy as a child process)

Protocol coverage (MCP 2024-11-05 to 2025-06-18) is an explicit allow-list, not a blanket pass-through:

    client -> server  tools/call and resources/read are gated by the policy; lifecycle, discovery, prompts,
                      completion, logging and subscriptions pass; any other request method is refused
                      with -32601 (fail closed), and a tools/call or resources/read sent without an id
                      (notification-shaped, so it could execute without a reply) is dropped.
    server -> client  sampling/createMessage (a server asking the client's model to generate) is refused
                      unless PROVENANT_ALLOW_SAMPLING=1; roots/list, elicitation/create and ping pass;
                      other requests are refused. Results of tools/call, resources/read and prompts/get are
                      scanned as untrusted content.

On top of the per-call policy the proxy:

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
from .guard import ALLOW, APPROVE, DENY, Guard, GuardCall
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


CLIENT_PASS = {"initialize", "ping", "tools/list", "resources/list", "resources/templates/list", "prompts/list",
               "prompts/get", "completion/complete", "logging/setLevel", "resources/subscribe", "resources/unsubscribe"}
GATED = {"tools/call", "resources/read"}
SERVER_PASS = {"ping", "roots/list", "elicitation/create"}
UNTRUSTED_RESULTS = {"call", "resource", "prompt"}


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
        self._upstream_alive = True
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
    def _upstream_gone(self) -> None:
        """The real server exited: answer every in-flight request so the agent never hangs, and never resend."""
        with self._lock:
            if not self._upstream_alive:
                return
            self._upstream_alive = False
            pending, self._pending = self._pending, {}
        code = self.proc.poll()
        self.guard.audit.append("upstream_exit", self.session_id, {"server": self.name, "returncode": code,
                                                                   "in_flight": len(pending)})
        for key, kind in pending.items():
            note = " Its outcome is unknown: the call was allowed and may have partly run." if kind[0] == "call" else ""
            self._error(json.loads(key), -32000, f"Provenant: the '{self.name}' MCP server exited "
                                                 f"(code {code}) before answering.{note}")

    def on_client(self, msg: dict) -> None:
        method, mid = msg.get("method"), msg.get("id")
        if not self._upstream_alive:
            if mid is not None and method is not None:
                self._error(mid, -32000, f"Provenant: the '{self.name}' MCP server is not running; nothing was sent")
            return
        if method is None:                       # a response to a server->client request
            self._send_upstream(msg)
            return
        if not isinstance(method, str):
            self._error(mid, -32600, "invalid request: method must be a string")
            return
        if mid is None:                          # notification
            if method in GATED:
                self.guard.audit.append("protocol_refused", self.session_id,
                                        {"method": method, "reason": "gated method sent as a notification"})
                return                           # dropped: it would run with no reply and no gate
            if method.startswith("notifications/"):
                self._send_upstream(msg)
            return
        if method == "initialize":
            p = msg.get("params") or {}
            self.guard.audit.append("mcp_initialize", self.session_id,
                                    {"protocolVersion": str(p.get("protocolVersion"))[:40],
                                     "client": str((p.get("clientInfo") or {}).get("name"))[:80]})
        if method == "tools/list":
            self._pending[_key(mid)] = ("list", None)
        elif method == "tools/call":
            if not self._gate_call(msg):
                return
        elif method == "resources/read":
            if not self._gate_resource(msg):
                return
        elif method == "prompts/get":
            self._pending[_key(mid)] = ("prompt", str((msg.get("params") or {}).get("name")))
        elif method not in CLIENT_PASS:
            self.guard.audit.append("protocol_refused", self.session_id, {"method": method[:80]})
            self._error(mid, -32601, f"Provenant: method '{method[:80]}' is not on the proxy's allow-list")
            return
        self._send_upstream(msg)

    def _error(self, mid, code: int, message: str) -> None:
        self._send_client({"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}})

    def _gate_resource(self, msg: dict) -> bool:
        mid, uri = msg.get("id"), (msg.get("params") or {}).get("uri")
        try:
            if not isinstance(uri, str):
                raise ValueError("uri missing")
            args = {"uri": uri}
            if uri.lower().startswith("file://"):
                from urllib.parse import unquote, urlsplit
                parts = urlsplit(uri)
                path = unquote(parts.path)
                if re.match(r"^[A-Za-z]:", parts.netloc):                 # file://C:\x or file://C:/x (non-standard)
                    path = unquote(parts.netloc + parts.path)
                elif re.match(r"^/[A-Za-z]:", path):                       # file:///C:/x -> C:/x
                    path = path[1:]
                args["path"] = path
            call = GuardCall(self._qualified("resources_read"), args, self.session_id, self.workspace, "mcp")
            v = self.guard.check(call, hold=True)
            if v.decision == ALLOW and not self.guard.redeem(v, call):
                raise RuntimeError("grant could not be redeemed")
        except Exception as exc:
            self._refuse(mid, f"DENY: Provenant could not evaluate this read ({type(exc).__name__}); failing closed", "DENY")
            return False
        if v.decision != ALLOW:
            self._refuse(mid, v.message(), v.decision.value, v.approval_id)
            return False
        self._pending[_key(mid)] = ("resource", "resources_read")
        return True

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
            call = GuardCall(self._qualified(name), args if args is not None else {}, self.session_id,
                             self.workspace, "mcp")
            v = self.guard.check(call, hold=True)
        except Exception as exc:            # fail closed
            self._refuse(mid, f"DENY: Provenant could not evaluate this call ({type(exc).__name__}); failing closed", "DENY")
            return False
        if v.decision in (DENY, APPROVE):
            self._refuse(mid, v.message(), v.decision.value, v.approval_id)
            _notify(f"[provenant] {v.decision.value} {self.name}.{name}: {'; '.join(v.reasons)[:200]}")
            return False
        if not self.guard.redeem(v, call):  # the grant is the only thing that lets a call through
            self._refuse(mid, "DENY: Provenant could not redeem the execution grant; failing closed", "DENY")
            return False
        self._pending[_key(mid)] = ("call", name)
        return True

    def _refuse(self, mid, text: str, decision: str, approval_id: str | None = None) -> None:
        self._send_client({"jsonrpc": "2.0", "id": mid,
                           "result": {"isError": True, "content": [{"type": "text", "text": text}],
                                      "_meta": {"provenant": {"decision": decision, "approval_id": approval_id}}}})

    # --- server -> client ----------------------------------------------------------------------
    def on_upstream(self, msg: dict) -> None:
        method = msg.get("method")
        if isinstance(method, str) and msg.get("id") is not None:      # server -> client request
            allowed = method in SERVER_PASS or (method == "sampling/createMessage"
                                                and os.environ.get("PROVENANT_ALLOW_SAMPLING") == "1")
            if not allowed:
                self.guard.audit.append("protocol_refused", self.session_id, {"method": method[:80], "direction": "server"})
                self._send_upstream({"jsonrpc": "2.0", "id": msg["id"],
                                     "error": {"code": -32601, "message": f"Provenant: '{method[:80]}' refused by policy"}})
                return
        if "method" not in msg and "id" in msg:
            kind = self._pending.pop(_key(msg["id"]), None)
            if kind and kind[0] == "list" and isinstance(msg.get("result"), dict):
                tools, withheld = self.pins.review(msg["result"].get("tools") or [])
                msg["result"]["tools"] = tools
                if withheld:
                    self.guard.audit.append("manifest_withheld", self.session_id, {"withheld": withheld})
                    _notify(f"[provenant] withheld tools from {self.name}: {sorted(withheld)}")
            elif kind and kind[0] in UNTRUSTED_RESULTS:
                result = msg.get("result")
                try:
                    # Mail scanning is observational: it never changes the MCP result or decides
                    # whether a tool call may run. The deterministic policy remains authoritative.
                    from .mail_security import process_result
                    reports = process_result(
                        result, self.name, kind[1],
                        audit=lambda event, data: self.guard.audit.append(event, self.session_id, data),
                    )
                    for report in reports:
                        if report["verdict"] == "high":
                            _notify(f"[provenant] HIGH-RISK EMAIL from {report['sender_domain']}: "
                                    f"{report['subject'][:100]} (score {report['risk_score']})")
                except Exception as exc:
                    self.guard.audit.append("mail_scan_error", self.session_id,
                                            {"server": self.name, "tool": str(kind[1])[:100],
                                             "error": type(exc).__name__})
                try:
                    flags = self.guard.ingest_output(self.session_id, self._qualified(kind[1]), result)
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
        self.proc.wait()
        self._upstream_gone()

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
                        except (BrokenPipeError, OSError, ValueError):     # upstream stdin closed under us
                            self._upstream_gone()
                            if m.get("id") is not None and m.get("method") is not None:
                                self._error(m["id"], -32000, f"Provenant: the '{self.name}' MCP server is not running")
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
