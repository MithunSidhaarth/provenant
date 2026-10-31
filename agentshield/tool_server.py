"""provenant-tools: an MCP server whose tools are executed BY the gateway, so policy is not advisory here.

    agent ──tools/call──▶ ToolGateway.call ──▶ Guard.check (policy) ──▶ Guard.redeem (single-use grant)
                                                                     ──▶ the tool runs ──▶ audit + efficiency

Structured tools come first (read_file, list_directory, search_text, run_tests, write_file, http_get).
Arbitrary commands (run_command) exist only when the server is started with --allow-shell, run without a
shell (argv split, so no pipes or redirection), and still go through the shell rules of the policy. Those
rules are pattern checks, not isolation: an allowed program can do anything its user can.

Registered tools only: an unknown name is refused with -32602 and audited. There is no fallback path that
runs a call without a redeemed grant; any exception while authorizing returns an error and runs nothing.
http_get uses netguard.safe_fetch (resolved-address pinning, redirect revalidation).

Scope: this protects calls that go through this server. It cannot stop an agent that also has its own shell
or file tools from using them; pair it with the Claude Code hook or remove those tools from the client.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .efficiency import Efficiency, env_bool
from .guard import ALLOW, Guard, GuardCall
from .models import new_id
from .netguard import DestinationRefused, safe_fetch

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
SERVER_NAME = "provenant"

TOOLS: dict[str, dict] = {
    "read_file": {"description": "Read a UTF-8 text file inside the workspace. Long files are shortened unless full is true.",
                  "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "offset": {"type": "integer"},
                                  "limit": {"type": "integer"}, "full": {"type": "boolean"}}, "required": ["path"]}},
    "list_directory": {"description": "List files under a directory (vendored and generated folders skipped unless full).",
                       "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "depth": {"type": "integer"},
                                       "full": {"type": "boolean"}}, "required": ["path"]}},
    "search_text": {"description": "Search files under a directory for a regular expression.",
                    "inputSchema": {"type": "object", "properties": {"pattern": {"type": "string"}, "path": {"type": "string"},
                                    "glob": {"type": "string"}, "full": {"type": "boolean"}}, "required": ["pattern", "path"]}},
    "run_tests": {"description": "Run the project's configured test command (no arguments from the agent). Output keeps failures and the summary.",
                  "inputSchema": {"type": "object", "properties": {"full": {"type": "boolean"}}}},
    "write_file": {"description": "Write a UTF-8 text file inside the workspace.",
                   "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                                   "required": ["path", "content"]}},
    "http_get": {"description": "HTTP GET an allowed public URL. Private, loopback and metadata addresses are refused at connect time.",
                 "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}},
}
SHELL_TOOL = {"run_command": {"description": "Run one program with arguments (no shell features). Opt-in; still policy-checked.",
                              "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}}}


class ToolError(Exception):
    pass


class ToolGateway:
    def __init__(self, workspace: str, guard: Guard | None = None, allow_shell: bool = False,
                 test_cmd: list[str] | None = None, efficiency: Efficiency | None = None, session_id: str | None = None,
                 fetcher=safe_fetch) -> None:
        self.guard = guard or Guard()
        self.workspace = str(Path(workspace).resolve())
        self.allow_shell = allow_shell
        self.test_cmd = test_cmd or _detect_tests(Path(self.workspace))
        self.eff = efficiency or Efficiency()
        self.session_id = session_id or f"mcp:{SERVER_NAME}:{new_id('s')}"
        self.fetcher = fetcher
        self.calls = 0

    def tool_list(self) -> list[dict]:
        tools = {**TOOLS, **(SHELL_TOOL if self.allow_shell else {})}
        return [{"name": n, **d} for n, d in tools.items()]

    # --- the single entry point ------------------------------------------------------------------
    def call(self, name: Any, args: Any) -> dict:
        """Returns an MCP CallToolResult. Never raises."""
        self.calls += 1
        registered = {t["name"] for t in self.tool_list()}
        if not isinstance(name, str) or name not in registered:
            self.guard.audit.append("unknown_tool_refused", self.session_id, {"tool": str(name)[:80]})
            return _result(f"DENY: '{str(name)[:80]}' is not a registered Provenant tool", True, "DENY")
        args = args if isinstance(args, dict) else None
        if args is None:
            return _result("DENY: arguments must be an object", True, "DENY")
        call = GuardCall(f"mcp__{SERVER_NAME}__{name}", args, self.session_id, self.workspace, "provenant-tools")
        try:
            v = self.guard.check(call, hold=True)
            if v.decision != ALLOW:
                return _result(v.message(), True, v.decision.value, v.approval_id)
            if not self.guard.redeem(v, call):
                return _result("DENY: execution grant could not be redeemed; nothing ran", True, "DENY")
        except Exception as exc:
            return _result(f"DENY: authorization failed ({type(exc).__name__}); failing closed, nothing ran", True, "DENY")
        t0 = time.perf_counter()
        try:
            text = self._run(name, args)
            err = False
        except ToolError as exc:
            text, err = f"error: {exc}", True
        except Exception as exc:                # tool failure after authorization: report, never retry elsewhere
            text, err = f"error: {type(exc).__name__}: {exc}", True
        if not err and name in ("read_file", "http_get", "search_text"):
            try:
                self.guard.ingest_output(self.session_id, call.tool, text)
            except Exception:
                pass
        self.guard.audit.append("tool_executed", self.session_id, {"call_id": call.call_id, "tool": name, "error": err,
                                                                   "ms": round((time.perf_counter() - t0) * 1000, 2),
                                                                   "chars": len(text)})
        return _result(text, err, "ALLOW")

    # --- tools --------------------------------------------------------------------------------
    def _path(self, raw: Any) -> Path:
        if not isinstance(raw, str) or not raw:
            raise ToolError("path must be a non-empty string")
        p = Path(raw).expanduser()
        p = (p if p.is_absolute() else Path(self.workspace) / p).resolve()   # resolve() follows symlinks
        ws = Path(self.workspace)
        if p != ws and ws not in p.parents:
            raise ToolError(f"{raw} resolves outside the workspace")         # defence in depth after the policy
        return p

    def _run(self, name: str, a: dict) -> str:
        full = bool(a.get("full"))
        if name in ("read_file", "list_directory", "search_text"):
            p = self._path(a.get("path"))
            key = self.eff.key(name, a, self.session_id, self.guard.mode, self.guard.policy.version, [p])
            cached = self.eff.lookup(name, key)
            if cached is not None:
                self.eff.stats.cache_hits += 1
                raw = cached
            else:
                raw = getattr(self, "_" + name)(p, a)
                self.eff.store(name, key, raw)
            shaped = self._shape(name, raw, full)
            out = self.eff.dedupe(name, key, shaped, self.calls, full)
            self.eff.note(raw, out)
            return out
        if name == "run_tests":
            if not self.test_cmd:
                raise ToolError("no test command configured (start the server with --test-cmd)")
            p = subprocess.run(self.test_cmd, cwd=self.workspace, capture_output=True, text=True, timeout=600)
            raw = (p.stdout + "\n" + p.stderr).strip()
            out = self.eff.tests(raw, p.returncode, full)
            self.eff.note(raw, out)
            return out
        if name == "write_file":
            p = self._path(a.get("path"))
            content = a.get("content")
            if not isinstance(content, str):
                raise ToolError("content must be a string")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            return f"wrote {len(content)} chars to {p.relative_to(self.workspace)}"
        if name == "http_get":
            allowed = self.guard.policy.config["network"]["allowed_hosts"]
            try:
                r = self.fetcher(str(a.get("url")), host_allowed=lambda h: any(
                    fnmatch.fnmatchcase(h, pat) or h == pat.lstrip("*.") for pat in allowed))
            except DestinationRefused as exc:
                raise ToolError(f"destination refused at connect time: {exc}")
            body = self.eff.file(r["body"], full)
            self.eff.note(r["body"], body)
            return f"HTTP {r['status']} {r['url']}\n\n{body}"
        if name == "run_command":
            argv = shlex.split(str(a.get("command", "")))
            if not argv:
                raise ToolError("empty command")
            p = subprocess.run(argv, cwd=self.workspace, capture_output=True, text=True, timeout=300)
            return (p.stdout + p.stderr)[-20000:] + f"\n[exit {p.returncode}]"
        raise ToolError("unreachable")

    def _shape(self, name: str, raw: str, full: bool) -> str:
        if name == "read_file":
            return self.eff.file(raw, full)
        if name == "list_directory":
            return "\n".join(self.eff.listing(raw.splitlines(), full))
        if name == "search_text":
            lines = raw.splitlines()
            if self.eff.enabled and not full and len(lines) > self.eff.max_matches:
                return "\n".join(lines[: self.eff.max_matches] + [f"[provenant] … {len(lines) - self.eff.max_matches} more matches"])
        return raw

    def _read_file(self, p: Path, a: dict) -> str:
        if not p.is_file():
            raise ToolError(f"{a.get('path')} is not a file")
        text = p.read_text(encoding="utf-8", errors="replace")
        off, lim = a.get("offset"), a.get("limit")
        if isinstance(off, int) or isinstance(lim, int):
            lines = text.splitlines(keepends=True)
            o = max(0, int(off or 0))
            text = "".join(lines[o: o + int(lim)] if isinstance(lim, int) else lines[o:])
        return text

    def _list_directory(self, p: Path, a: dict) -> str:
        if not p.is_dir():
            raise ToolError(f"{a.get('path')} is not a directory")
        depth = min(int(a.get("depth") or 2), 6)
        full = bool(a.get("full"))
        out = []

        def walk(d: Path, level: int):
            for c in sorted(d.iterdir(), key=lambda x: (not x.is_dir(), x.name)):
                rel = c.relative_to(p).as_posix()
                if c.is_dir():
                    if self.eff.skip_dir(c.name, full):
                        out.append(rel + "/ [skipped]")
                        continue
                    out.append(rel + "/")
                    if level < depth:
                        walk(c, level + 1)
                else:
                    out.append(f"{rel}  {c.stat().st_size}B")
        walk(p, 1)
        return "\n".join(out)

    def _search_text(self, p: Path, a: dict) -> str:
        try:
            rx = re.compile(str(a.get("pattern")))
        except re.error as exc:
            raise ToolError(f"bad pattern: {exc}")
        glob = str(a.get("glob") or "*")
        full = bool(a.get("full"))
        hits = []
        for root, dirs, files in os.walk(p):
            dirs[:] = sorted(d for d in dirs if not self.eff.skip_dir(d, full) and d != ".git")
            for f in sorted(files):
                if not fnmatch.fnmatch(f, glob):
                    continue
                fp = Path(root) / f
                try:
                    for i, line in enumerate(fp.read_text(encoding="utf-8", errors="strict").splitlines(), 1):
                        if rx.search(line):
                            hits.append(f"{fp.relative_to(p).as_posix()}:{i}: {line.strip()[:200]}")
                except (UnicodeDecodeError, OSError):
                    continue
        return "\n".join(hits) if hits else "no matches"


def _detect_tests(ws: Path) -> list[str] | None:
    env = os.environ.get("PROVENANT_TEST_CMD")
    if env:
        return shlex.split(env)
    if (ws / "tests").is_dir() and any((ws / "tests").glob("test_*.py")):
        return [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "."]
    if (ws / "package.json").is_file():
        return ["npm", "test", "--silent"]
    return None


def _result(text: str, is_error: bool, decision: str, approval_id: str | None = None) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": is_error,
            "_meta": {"provenant": {"decision": decision, "approval_id": approval_id}}}


# --- MCP stdio server -------------------------------------------------------------------------------
class MCPServer:
    def __init__(self, gw: ToolGateway, out=None) -> None:
        self.gw = gw
        self.out = out or sys.stdout
        self.initialized = False

    def handle(self, msg: Any) -> dict | None:
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
        method, mid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
        if method is None:
            return None                                      # a response to us; we send no requests
        if mid is None:
            return None                                      # notifications (initialized, cancelled) need no reply
        if not isinstance(params, dict):
            return _err(mid, -32602, "params must be an object")
        if method == "initialize":
            asked = params.get("protocolVersion")
            self.initialized = True
            return _ok(mid, {"protocolVersion": asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                             "capabilities": {"tools": {"listChanged": False}, "resources": {}, "prompts": {}, "logging": {}},
                             "serverInfo": {"name": "provenant-tools", "version": _version()},
                             "instructions": "Every tool call is checked by Provenant's deterministic policy before it runs. "
                                             "DENY means nothing ran; REQUIRE_APPROVAL means a human must approve the exact call."})
        if method == "ping":
            return _ok(mid, {})
        if not self.initialized:
            return _err(mid, -32002, "server not initialized")
        if method == "tools/list":
            return _ok(mid, {"tools": self.gw.tool_list()})
        if method == "tools/call":
            return _ok(mid, self.gw.call(params.get("name"), params.get("arguments", {})))
        if method in ("resources/list", "resources/templates/list"):
            return _ok(mid, {"resources": [], "resourceTemplates": []} if method.endswith("templates/list")
                       else {"resources": []})
        if method == "prompts/list":
            return _ok(mid, {"prompts": []})
        if method == "logging/setLevel":
            return _ok(mid, {})
        return _err(mid, -32601, f"method not supported: {str(method)[:80]}")

    def run(self, inp=None) -> int:
        for line in (inp or sys.stdin):
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                self._send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
                continue
            replies = [r for r in (self.handle(m) for m in (msg if isinstance(msg, list) else [msg])) if r]
            if replies:
                self._send(replies if isinstance(msg, list) else replies[0])
        return 0

    def _send(self, obj) -> None:
        self.out.write(json.dumps(obj, ensure_ascii=False) + "\n")
        self.out.flush()


def _ok(mid, result):
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid, code, message):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def _version() -> str:
    from .cli import VERSION          # the distribution is "provenant-agent-shield", not "provenant"
    return VERSION


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="provenant serve", description="Provenant's own policy-gated MCP tool server.")
    ap.add_argument("--workspace", default=os.environ.get("PROVENANT_WORKSPACE", os.getcwd()))
    ap.add_argument("--allow-shell", action="store_true", help="expose run_command (still policy-checked; not a sandbox)")
    ap.add_argument("--test-cmd", default=None, help="command run_tests executes, e.g. \"pytest -q\"")
    ap.add_argument("--no-efficiency", action="store_true", help="return raw tool output (no compression, cache or dedup)")
    ap.add_argument("--no-dedup", action="store_true")
    ns = ap.parse_args(argv)
    for stream in (sys.stdin, sys.stdout):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    eff = Efficiency(enabled=not ns.no_efficiency and env_bool("PROVENANT_EFFICIENCY", True),
                     dedup=not ns.no_dedup and env_bool("PROVENANT_DEDUP", True))
    gw = ToolGateway(ns.workspace, allow_shell=ns.allow_shell, test_cmd=shlex.split(ns.test_cmd) if ns.test_cmd else None,
                     efficiency=eff)
    return MCPServer(gw).run()


if __name__ == "__main__":
    raise SystemExit(main())
