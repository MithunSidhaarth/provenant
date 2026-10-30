"""Local HTTP server for the AgentShield dashboard. Standard library only.

Binds to 127.0.0.1 by default. State-changing approval calls require the custom header
X-AgentShield-Approver (a browser cannot send it cross-origin without a CORS preflight, which
this server never grants), plus a named human approver in the body.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import threading
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from . import fuzzer, redteam
from .policy import PolicyEngine
from .runner import Shield, Run
from .sandbox import ROOT
from .tools import TOOLS

DASHBOARD = ROOT / "dashboard"
STATIC = {"/": "index.html", "/app.js": "app.js", "/style.css": "style.css"}
CTYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
          ".css": "text/css; charset=utf-8"}
MAX_BODY = 64 * 1024


class App:
    def __init__(self, audit_dir: Path | None = None) -> None:
        self.lock = threading.RLock()
        self.audit_dir = audit_dir
        self.reset()

    def reset(self) -> None:
        path = None
        if self.audit_dir:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            path = self.audit_dir / f"audit-{stamp}-{os.getpid()}.jsonl"
        self.shield = Shield(audit_path=path)

    # --- API ---------------------------------------------------------------------------
    def scenarios(self) -> list[dict]:
        return list(self.shield.scenarios.values())

    def compare(self, sid: str) -> dict:
        return {"before": self.shield.run(sid, protected=False), "after": self.shield.run(sid, protected=True)}

    def playground(self, body: dict) -> dict:
        task = body.get("user_task", "")
        sc = {"id": "playground", "title": "Playground call", "kind": "custom", "category": "playground",
              "user_task": task if isinstance(task, str) else "",
              "plan": [{"raw": {"tool": body.get("tool"), "args": body.get("args")}, "source": "playground"}]}
        if isinstance(body.get("untrusted_context"), str):
            sc["prior_context"] = body["untrusted_context"][:5000]
        r = Run(sc, True, self.shield.audit, self.shield.engine)
        self.shield.runs[r.run_id] = r
        rep = r.execute()
        rep["verdict"] = rep["decisions"][0] if rep["decisions"] else "DENY"
        return rep

    def lab(self, body: dict) -> dict:
        content = body.get("content")
        if not isinstance(content, str) or not content.strip():
            raise ValueError("content must be a non-empty string")
        task = body.get("user_task") if isinstance(body.get("user_task"), str) and body["user_task"].strip() else fuzzer.LAB_TASK
        sc = fuzzer.lab_scenario(content[:20000], task[:500])
        out = {}
        for name, protected in (("before", False), ("after", True)):
            r = Run(sc, protected, self.shield.audit, self.shield.engine)
            self.shield.runs[r.run_id] = r
            out[name] = r.execute()
        return out

    def fuzz(self) -> dict:
        rep = fuzzer.run_campaign(self.shield.engine)
        self.shield.audit.append("fuzz_campaign", "fuzzer", {"summary": rep["summary"], "classes": rep["classes"]})
        return rep

    def tamper_demo(self) -> dict:
        entries = copy.deepcopy(self.shield.audit.entries)
        target = next((i for i, e in enumerate(entries) if e["event"] == "policy_decision"
                       and e["data"].get("decision") == "DENY"), None)
        if target is None:
            return {"ok": False, "reason": "run an attack scenario first so there is a DENY to forge"}
        before = entries[target]["data"]["decision"]
        entries[target]["data"]["decision"] = "ALLOW"
        return {"ok": True, "tampered_seq": target, "change": f"decision {before} -> ALLOW",
                "verification_of_tampered_copy": self.shield.audit.verify(entries),
                "verification_of_real_log": self.shield.audit.verify()}

    def ablation(self) -> dict:
        attacks = [k for k, v in self.shield.scenarios.items() if v["kind"] == "attack"]
        rows = []
        for rule in ("none",) + PolicyEngine.RULES:
            s = Shield(engine=PolicyEngine.from_file(disabled_rules=() if rule == "none" else (rule,)))
            row = {"disabled_rule": rule, "results": {}}
            for sid in attacks:
                rep = s.run(sid, protected=True)
                row["results"][sid] = [h["id"] for h in rep["outcome"]["harms"]]
            rows.append(row)
        return {"scenarios": attacks, "rows": rows}

    def policy(self) -> dict:
        tools = [{"name": t.name, "description": t.description, "permission": t.permission,
                  "side_effect": t.side_effect, "high_impact": t.high_impact, "untrusted_output": t.untrusted_output,
                  "args": {k: {"type": a.type, "control": a.control} for k, a in t.args.items()}}
                 for t in TOOLS.values()]
        return {"config": self.shield.engine.config, "load_error": self.shield.engine.load_error,
                "rules": ["structure", "known_tool", "schema", *PolicyEngine.RULES], "tools": tools}


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AgentShield/1.0"

        def log_message(self, fmt, *args):  # keep the console quiet; the audit log is the record
            pass

        def _send(self, status: int, payload, ctype="application/json; charset=utf-8"):
            data = payload if isinstance(payload, bytes) else json.dumps(payload, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
                             "font-src https://fonts.gstatic.com; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(data)

        def _err(self, status: int, msg: str):
            self._send(status, {"error": msg})

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                raise ValueError("request body too large")
            raw = self.rfile.read(n) if n else b"{}"
            body = json.loads(raw or b"{}")
            if not isinstance(body, dict):
                raise ValueError("body must be a JSON object")
            return body

        def do_GET(self):
            u = urlparse(self.path)
            if u.path in STATIC:
                f = DASHBOARD / STATIC[u.path]
                return self._send(200, f.read_bytes(), CTYPES[f.suffix])
            q = parse_qs(u.query)
            with app.lock:
                if u.path == "/api/scenarios":
                    return self._send(200, app.scenarios())
                if u.path == "/api/policy":
                    return self._send(200, app.policy())
                if u.path == "/api/approvals":
                    return self._send(200, app.shield.pending_approvals())
                if u.path == "/api/audit":
                    entries = app.shield.audit.entries
                    sid = q.get("session_id", [None])[0]
                    if sid:
                        entries = [e for e in entries if e["session_id"] == sid]
                    return self._send(200, {"entries": entries[-500:], "total": len(app.shield.audit.entries)})
                if u.path == "/api/audit/verify":
                    return self._send(200, app.shield.audit.verify())
                if u.path == "/api/redteam":
                    rep = redteam.run(app.shield.engine)
                    app.shield.audit.append("redteam_run", "redteam", {
                        "findings": [{"mutation": f["mutation"], "kind": f["kind"],
                                      "proposal": (f["proposal"] or {}).get("change")} for f in rep["findings"]]})
                    return self._send(200, rep)
                if u.path == "/api/fuzz":
                    return self._send(200, app.fuzz())
                if u.path == "/api/ablation":
                    return self._send(200, app.ablation())
            return self._err(404, "not found")

        def do_POST(self):
            u = urlparse(self.path)
            try:
                body = self._body()
            except (ValueError, json.JSONDecodeError) as exc:
                return self._err(400, f"bad request: {exc}")
            with app.lock:
                try:
                    if u.path == "/api/run":
                        sid = body.get("scenario_id")
                        if sid not in app.shield.scenarios:
                            return self._err(404, "unknown scenario")
                        return self._send(200, app.shield.run(sid, protected=body.get("protected", True) is not False))
                    if u.path == "/api/compare":
                        sid = body.get("scenario_id")
                        if sid not in app.shield.scenarios:
                            return self._err(404, "unknown scenario")
                        return self._send(200, app.compare(sid))
                    if u.path.startswith("/api/approvals/"):
                        if self.headers.get("X-AgentShield-Approver") != "1":
                            return self._err(403, "approval requests must come from the dashboard")
                        if not isinstance(body.get("approve"), bool):
                            return self._err(400, "'approve' must be true or false")
                        aid = u.path.rsplit("/", 1)[-1]
                        return self._send(200, app.shield.decide(aid, body.get("approver"), body["approve"],
                                                                 str(body.get("note", ""))[:300]))
                    if u.path == "/api/lab":
                        try:
                            return self._send(200, app.lab(body))
                        except ValueError as exc:
                            return self._err(400, str(exc))
                    if u.path == "/api/playground":
                        return self._send(200, app.playground(body))
                    if u.path == "/api/audit/tamper-demo":
                        return self._send(200, app.tamper_demo())
                    if u.path == "/api/reset":
                        app.reset()
                        return self._send(200, {"ok": True})
                except Exception as exc:   # never leak a stack trace; the request simply fails
                    return self._err(500, f"internal error: {type(exc).__name__}")
            return self._err(404, "not found")

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8765, audit_dir: Path | None = ROOT / "data") -> ThreadingHTTPServer:
    app = App(audit_dir)
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    httpd.app = app
    return httpd


def main() -> None:
    ap = argparse.ArgumentParser(description="AgentShield dashboard")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--open", action="store_true", help="open the dashboard in the default browser")
    args = ap.parse_args()
    httpd = serve(args.host, args.port)
    url = f"http://{args.host}:{args.port}/"
    print(f"AgentShield dashboard: {url}  (Ctrl+C to stop)")
    if args.open:
        import webbrowser
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
