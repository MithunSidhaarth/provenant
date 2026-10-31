"""v8 live runtime: SQLite authorization state, grants, phone approval, network boundary, gateway tool server,
anchoring/retention, privacy and the policy simulator. Every test uses a temp PROVENANT_HOME."""
import http.server
import json
import multiprocessing
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path

from agentshield import anchor, netguard, voice
from agentshield.efficiency import Efficiency
from agentshield.guard import ALLOW, APPROVE, DENY, Guard, GuardCall, GuardPolicy, Store, DEFAULT_GUARD_POLICY
from agentshield.policysim import lint, run_scenarios
from agentshield.state import StateDB, StateUnavailable
from agentshield.tool_server import MCPServer, ToolGateway

ROOT = Path(__file__).resolve().parent.parent


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "pv"
        self.ws = Path(self.tmp.name) / "work"
        self.ws.mkdir()
        os.environ.pop("AGENTSHIELD_AUDIT_KEY", None)
        self.guard = Guard(store=Store(self.home, mode="live"))

    def tearDown(self):
        self.tmp.cleanup()

    def hold(self, tool="mcp__slack__send_message", args=None, sid="s1", guard=None):
        g = guard or self.guard
        call = GuardCall(tool, args or {"channel": "#ops", "text": "deploy done"}, sid, str(self.ws))
        v = g.check(call)
        self.assertEqual(v.decision, APPROVE)
        return call, v


def _consume_worker(home, fp, q):
    db = StateDB(Path(home) / "state.db")
    q.put(db.consume_approval(fp, "live", time.time(), f"call-{os.getpid()}") is not None)


class ApprovalState(Base):
    def test_approval_is_single_use_and_bound_to_exact_args(self):
        call, v = self.hold()
        self.assertTrue(self.guard.decide(v.approval_id, "human:mithun", True)["ok"])
        changed = GuardCall(call.tool, {"channel": "#ops", "text": "deploy done!"}, call.session_id, call.workspace)
        self.assertEqual(self.guard.check(changed).decision, APPROVE)          # changed args need a new approval
        first = self.guard.check(GuardCall(call.tool, call.args, call.session_id, call.workspace))
        self.assertEqual(first.decision, ALLOW)
        replay = self.guard.check(GuardCall(call.tool, call.args, call.session_id, call.workspace))
        self.assertEqual(replay.decision, APPROVE)                              # replay: used up

    def test_concurrent_consumers_only_one_wins(self):
        call, v = self.hold()
        self.guard.decide(v.approval_id, "human:mithun", True)
        q = multiprocessing.get_context("spawn").Queue()
        ps = [multiprocessing.get_context("spawn").Process(target=_consume_worker, args=(str(self.home), v.fingerprint, q))
              for _ in range(8)]
        for p in ps:
            p.start()
        for p in ps:
            p.join(30)
        wins = [q.get(timeout=5) for _ in ps]
        self.assertEqual(sum(wins), 1)

    def test_expired_approval_does_not_unlock(self):
        clock = [1000.0]
        g = Guard(store=self.guard.store, clock=lambda: clock[0])
        call, v = self.hold(guard=g)
        g.decide(v.approval_id, "human:mithun", True)
        clock[0] += 10_000
        self.assertEqual(g.check(GuardCall(call.tool, call.args, call.session_id, call.workspace)).decision, APPROVE)

    def test_demo_approvals_never_authorize_live(self):
        demo = Guard(store=Store(self.home, mode="demo"))
        call, v = self.hold(guard=demo)
        demo.decide(v.approval_id, "human:mithun", True)
        live_v = self.guard.check(GuardCall(call.tool, call.args, call.session_id, call.workspace))
        self.assertEqual(live_v.decision, APPROVE)
        self.assertNotEqual((self.home / "state.db").stat().st_ino, (self.home / "demo-state.db").stat().st_ino)

    def test_agent_and_unknown_channels_cannot_approve(self):
        call, v = self.hold()
        self.assertFalse(self.guard.decide(v.approval_id, "agent:claude", True)["ok"])
        self.assertFalse(self.guard.decide(v.approval_id, "human:x", True, channel="voice-agent")["ok"])

    def test_grant_is_single_use_and_call_bound(self):
        call = GuardCall("Read", {"file_path": str(self.ws / "a.txt")}, "s1", str(self.ws))
        v = self.guard.check(call)
        self.assertEqual(v.decision, ALLOW)
        other = GuardCall("Read", {"file_path": str(self.ws / "b.txt")}, "s1", str(self.ws))
        self.assertFalse(self.guard.redeem(v, other))
        self.assertTrue(self.guard.redeem(v, call))
        self.assertFalse(self.guard.redeem(v, call))

    def test_corrupt_state_fails_closed(self):
        db = self.home / "state.db"
        self.guard.check(GuardCall("Read", {"file_path": "x"}, "s1", str(self.ws)))
        for f in self.home.glob("state.db*"):
            f.write_bytes(b"this is not a database" * 100)
        with self.assertRaises(StateUnavailable):
            Store(self.home, mode="live")
        from agentshield import cc_hook
        os.environ["PROVENANT_HOME"] = str(self.home)
        try:
            out = cc_hook.handle({"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "x"},
                                  "session_id": "s", "cwd": str(self.ws)})
        finally:
            os.environ.pop("PROVENANT_HOME")
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertTrue(db.exists())

    def test_newer_schema_fails_closed(self):
        c = sqlite3.connect(self.home / "state.db")
        c.execute("PRAGMA user_version=99")
        c.close()
        with self.assertRaises(StateUnavailable):
            StateDB(self.home / "state.db")

    def test_backup_is_consistent(self):
        self.hold()
        self.guard.store.db.backup(self.home / "backup.db")
        self.assertEqual(len(StateDB(self.home / "backup.db").list_approvals()), 1)


class PhoneApproval(Base):
    def run_phone(self, transcript, status="completed", voicemail=False, code_override=None):
        call, v = self.hold()
        appr = self.guard.get_approval(v.approval_id)
        code = voice.confirmation_code(appr, self.guard.store.key)
        if code_override == "wrong":
            code = f"{(int(code) + 1) % 10000:04d}"
        seen = {}

        def runner(task):
            seen["task"] = task
            return {"status": status, "voicemail": voicemail, "execution_id": "ex1",
                    "transcript": transcript.replace("{code}", " ".join(code))}
        r = voice.phone_approve(self.guard, v.approval_id, runner=runner)
        return call, v, r, seen

    def test_explicit_coded_approval_unlocks_exactly_once(self):
        call, v, r, seen = self.run_phone("assistant: Provenant paused a Slack message.\nuser: What will it say?\n"
                                          "assistant: deploy done.\nuser: approve {code}")
        self.assertTrue(r["approved"], r)
        self.assertIn("deploy done", seen["task"])
        self.assertEqual(self.guard.check(GuardCall(call.tool, call.args, call.session_id, call.workspace)).decision, ALLOW)
        self.assertEqual(self.guard.check(GuardCall(call.tool, call.args, call.session_id, call.workspace)).decision, APPROVE)
        a = self.guard.get_approval(v.approval_id)
        self.assertEqual((a["channel"], a["status"]), ("phone", "used"))

    def test_questions_voicemail_timeouts_and_ambiguity_stay_blocked(self):
        cases = [
            ("assistant: hi\nuser: can you approve {code}?", "completed", False),        # a question
            ("assistant: hi\nuser: approve {code}", "completed", True),                  # voicemail
            ("", "no-answer", False),                                                    # no answer
            ("assistant: hi\nuser: approve {code}", "error", False),                     # provider failure
            ("assistant: hi\nuser: yes go ahead", "completed", False),                   # no code
            ("assistant: hi\nuser: approve {code}\nuser: actually no, deny", "completed", False),   # mixed
            ("assistant: approve {code}", "completed", False),                           # only the agent said it
        ]
        for transcript, status, vm in cases:
            with self.subTest(transcript=transcript, status=status):
                call, v, r, _ = self.run_phone(transcript, status, vm)
                self.assertFalse(r["approved"], r)
                self.assertNotEqual(self.guard.check(GuardCall(call.tool, call.args, call.session_id, call.workspace)).decision,
                                    ALLOW)

    def test_code_from_another_request_does_not_match(self):
        _, _, r, _ = self.run_phone("user: approve {code}", code_override="wrong")
        self.assertFalse(r["approved"])
        self.assertIn("code", r["reason"])

    def test_spoken_number_words_count(self):
        call, v = self.hold()
        code = voice.confirmation_code(self.guard.get_approval(v.approval_id), self.guard.store.key)
        words = " ".join(["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"][int(c)] for c in code)
        r = voice.phone_approve(self.guard, v.approval_id,
                                runner=lambda t: {"status": "completed", "transcript": f"user: I approve, {words}."})
        self.assertTrue(r["approved"], r)

    def test_runner_exception_and_refusal(self):
        call, v = self.hold()
        r = voice.phone_approve(self.guard, v.approval_id, runner=lambda t: 1 / 0)
        self.assertFalse(r["approved"])
        r = voice.phone_approve(self.guard, v.approval_id, runner=lambda t: {"status": "completed", "transcript": "user: deny"})
        self.assertEqual(self.guard.get_approval(v.approval_id)["status"], "rejected")

    def test_callme_output_parsing(self):
        out = 'created agent a1\nexecution_id x\n17:00:01 status=ringing\n{\n  "execution_id": "x",\n  "status": "completed",\n  "transcript": "user: hi"\n}'
        self.assertEqual(voice.parse_callme_output(out)["status"], "completed")
        self.assertEqual(voice.parse_callme_output("garbage")["status"], "error")


class Network(unittest.TestCase):
    def test_unusual_address_forms(self):
        for host in ("2130706433", "0x7f000001", "0x7f.1", "017700000001", "127.1", "[::1]", "[::ffff:127.0.0.1]",
                     "[::ffff:7f00:1]", "169.254.169.254", "10.1.2.3", "[fe80::1]", "0.0.0.0", "100.64.0.1",
                     "localhost", "metadata.google.internal", "svc.internal", "[64:ff9b::10.0.0.1]"):
            with self.subTest(host=host):
                self.assertIsNotNone(netguard.classify_host(host).restricted)
        self.assertIsNone(netguard.classify_host("docs.python.org").restricted)

    def test_static_url_checks(self):
        for url in ("file:///etc/passwd", "gopher://x.example/", "http://user:pw@x.example/", "http://[::1]:80/"):
            with self.assertRaises(netguard.DestinationRefused):
                netguard.validate_url(url)

    def test_rebinding_mixed_answers_refused(self):
        def resolver(host, port, *a):
            return [(2, 1, 6, "", ("93.184.216.34", port)), (2, 1, 6, "", ("127.0.0.1", port))]
        with self.assertRaises(netguard.DestinationRefused):
            netguard.resolve_checked("rebind.example", 80, resolver)

    def test_redirects_are_revalidated_and_connection_is_pinned(self):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                target = {"/meta": "http://169.254.169.254/latest", "/private": "http://intranet.example/x",
                          "/ok": None}[self.path]
                if target:
                    self.send_response(302)
                    self.send_header("Location", target)
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(f"host={self.headers['Host']}".encode())
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        port = srv.server_address[1]
        dns = {"public.example": "127.0.0.1", "intranet.example": "10.0.0.5"}
        resolver = lambda h, p, *a: [(2, 1, 6, "", (dns[h], p))]
        lab = lambda ip: None if str(ip) == "127.0.0.1" else netguard.restricted_reason(ip)   # test server only
        try:
            r = netguard.safe_fetch(f"http://public.example:{port}/ok", resolver=resolver, is_restricted=lab)
            self.assertEqual(r["status"], 200)
            self.assertIn("host=public.example", r["body"])          # connected to the pinned IP, Host kept
            for path in ("/meta", "/private"):
                with self.assertRaises(netguard.DestinationRefused):
                    netguard.safe_fetch(f"http://public.example:{port}{path}", resolver=resolver, is_restricted=lab)
        finally:
            srv.shutdown()


class ToolServer(Base):
    def gw(self, **kw):
        (self.ws / "app.py").write_text("def main():\n    return 42\n" * 2000, encoding="utf-8")
        (self.ws / ".env").write_text("TOKEN=ghp_" + "a" * 36, encoding="utf-8")
        return ToolGateway(str(self.ws), guard=self.guard, **kw)

    def text(self, r):
        return r["content"][0]["text"]

    def test_unknown_tools_and_shell_are_refused(self):
        gw = self.gw()
        self.assertEqual(gw.call("run_command", {"command": "id"})["_meta"]["provenant"]["decision"], "DENY")
        self.assertEqual(gw.call("delete_everything", {})["_meta"]["provenant"]["decision"], "DENY")
        self.assertEqual(gw.call("read_file", "nope")["_meta"]["provenant"]["decision"], "DENY")

    def test_secrets_traversal_and_symlink_escape(self):
        gw = self.gw()
        self.assertTrue(self.text(gw.call("read_file", {"path": ".env"})).startswith("DENY"))
        self.assertNotIn("ghp_", self.text(gw.call("read_file", {"path": "../work/.env"})))
        outside = Path(self.tmp.name) / "outside.txt"
        outside.write_text("outside secret", encoding="utf-8")
        (self.ws / "link.txt").symlink_to(outside)
        r = gw.call("read_file", {"path": "link.txt"})
        self.assertTrue(r["isError"])
        self.assertNotIn("outside secret", self.text(r))

    def test_cache_dedup_and_invalidation(self):
        gw = self.gw()
        a = self.text(gw.call("read_file", {"path": "app.py"}))
        self.assertIn("Outline", a)                                   # compressed to an outline
        b = self.text(gw.call("read_file", {"path": "app.py"}))
        self.assertIn("unchanged since your call", b)                 # dedup
        c = self.text(gw.call("read_file", {"path": "app.py", "full": True}))
        self.assertEqual(c.count("return 42"), 2000)                  # full on request
        time.sleep(0.01)
        (self.ws / "app.py").write_text("def main():\n    return 7\n", encoding="utf-8")
        d = self.text(gw.call("read_file", {"path": "app.py"}))
        self.assertIn("return 7", d)                                  # freshness key changed
        self.assertGreaterEqual(gw.eff.stats.cache_hits, 1)

    def test_search_and_listing_print_each_path_once(self):
        gw = self.gw()
        (self.ws / "pkg" / "sub").mkdir(parents=True)
        (self.ws / "pkg" / "sub" / "m.py").write_text("x = 1\nx = 2\n", encoding="utf-8")
        s = self.text(gw.call("search_text", {"pattern": "x =", "path": "pkg"}))
        self.assertEqual(s.splitlines(), ["sub/m.py", "  1: x = 1", "  2: x = 2"])
        self.assertIn("sub/m.py:1: x = 1", self.text(gw.call("search_text", {"pattern": "x =", "path": "pkg", "full": True})))
        self.assertEqual(self.text(gw.call("search_text", {"pattern": "nothing-here", "path": "pkg"})), "no matches")
        listing = self.text(gw.call("list_directory", {"path": "pkg", "depth": 3})).splitlines()
        self.assertEqual(listing, ["sub/", "  m.py  12B"])

    def test_authorization_is_never_cached(self):
        gw = self.gw()
        self.assertEqual(gw.call("read_file", {"path": "app.py"})["_meta"]["provenant"]["decision"], "ALLOW")
        self.guard.policy.config["tools"]["mcp__provenant__read_file"] = "DENY"
        self.assertEqual(gw.call("read_file", {"path": "app.py"})["_meta"]["provenant"]["decision"], "DENY")

    def test_writes_are_never_cached(self):
        gw = self.gw()
        gw.call("write_file", {"path": "out.txt", "content": "one"})
        (self.ws / "out.txt").unlink()
        gw.call("write_file", {"path": "out.txt", "content": "one"})
        self.assertEqual((self.ws / "out.txt").read_text(), "one")

    def test_broken_state_runs_nothing(self):
        gw = self.gw()
        gw.guard.store.db.path = Path("/nonexistent/dir/state.db")
        r = gw.call("write_file", {"path": "x.txt", "content": "1"})
        self.assertEqual(r["_meta"]["provenant"]["decision"], "DENY")
        self.assertFalse((self.ws / "x.txt").exists())

    def test_mcp_protocol(self):
        srv = MCPServer(self.gw())
        self.assertEqual(srv.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["error"]["code"], -32002)
        init = srv.handle({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}})
        self.assertEqual(init["result"]["protocolVersion"], "2025-03-26")
        self.assertIsNone(srv.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        names = {t["name"] for t in srv.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})["result"]["tools"]}
        self.assertNotIn("run_command", names)
        self.assertEqual(srv.handle({"jsonrpc": "2.0", "id": 4, "method": "sampling/createMessage"})["error"]["code"], -32601)
        self.assertEqual(srv.handle({"id": 5, "method": "ping"})["error"]["code"], -32600)
        self.assertEqual(srv.handle({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": "x"})["error"]["code"], -32602)


class AuditIntegrity(Base):
    def fill(self, n=6):
        for i in range(n):
            self.guard.check(GuardCall("Read", {"file_path": f"f{i}.txt"}, "s1", str(self.ws)))

    def test_truncation_detected_against_checkpoint(self):
        self.fill()
        anchor_dir = Path(self.tmp.name) / "anchor"
        self.assertTrue(anchor.checkpoint(self.guard, anchor_dir)["ok"])
        lines = self.guard.audit.path.read_text().splitlines()
        self.guard.audit.path.write_text("\n".join(lines[:5]) + "\n")       # valid shorter chain
        g2 = Guard(store=Store(self.home, mode="live"))
        self.assertTrue(g2.audit.verify()["ok"])                             # local check alone cannot tell
        r = anchor.verify_against(g2, anchor_dir)
        self.assertFalse(r["ok"])
        self.assertIn("truncated", r["problem"])

    def test_rewrite_with_the_local_key_detected(self):
        self.fill()
        anchor_dir = Path(self.tmp.name) / "anchor"
        anchor.checkpoint(self.guard, anchor_dir)
        from agentshield.audit import AuditLog
        forged = AuditLog(None, key=self.guard.store.key)                     # attacker holds the local key
        for e in self.guard.audit.snapshot():
            forged.append(e["event"], e["session_id"], {**e["data"], "note": "rewritten"} if e["seq"] == 2 else e["data"])
        self.guard.audit.path.write_text("".join(json.dumps(e) + "\n" for e in forged.entries))
        g2 = Guard(store=Store(self.home, mode="live"))
        self.assertTrue(g2.audit.verify()["ok"])
        self.assertFalse(anchor.verify_against(g2, anchor_dir)["ok"])

    def test_anchor_must_be_outside_home(self):
        self.fill(1)
        self.assertFalse(anchor.checkpoint(self.guard, self.home / "anchors")["ok"])

    def test_prune_keeps_chain_verifiable(self):
        self.fill(10)
        before = self.guard.audit.snapshot()[12]["seq"]
        r = anchor.prune(self.guard, before, Path(self.tmp.name) / "archive.jsonl")
        self.assertTrue(r["ok"], r)
        g2 = Guard(store=Store(self.home, mode="live"))
        self.assertTrue(g2.audit.verify()["ok"])
        self.assertEqual(g2.audit.snapshot()[0]["seq"], before)
        (self.home / "retention.json").write_text(json.dumps({"first_seq": 0, "prev_hash": "0" * 64, "mac": "x"}))
        self.assertFalse(Guard(store=Store(self.home, mode="live")).audit.verify()["ok"])   # forged retention record


class Privacy(Base):
    SECRET = "ghp_" + "Z" * 36

    def test_minimal_detail_keeps_no_argument_values(self):
        self.guard.check(GuardCall("Bash", {"command": "echo hello-private-value"}, "s1", str(self.ws)))
        raw = self.guard.audit.path.read_text()
        self.assertNotIn("hello-private-value", raw)
        self.assertIn("args_digest", raw)

    def test_secrets_redacted_even_with_full_detail(self):
        os.environ["PROVENANT_AUDIT_DETAIL"] = "full"
        try:
            self.guard.check(GuardCall("Bash", {"command": f"echo {self.SECRET} visible"}, "s1", str(self.ws)))
        finally:
            os.environ.pop("PROVENANT_AUDIT_DETAIL")
        raw = self.guard.audit.path.read_text()
        self.assertIn("visible", raw)
        self.assertNotIn(self.SECRET, raw)
        self.assertIn("REDACTED:github_token", raw)


class PolicySim(unittest.TestCase):
    def test_saved_scenarios_match_runtime(self):
        policy = GuardPolicy.from_file(DEFAULT_GUARD_POLICY)
        r = run_scenarios(policy, json.loads((ROOT / "evals" / "policy_scenarios.json").read_text()))
        self.assertEqual(r["passed"], r["total"], [x for x in r["rows"] if not x["pass"]])
        self.assertEqual([i for i in lint(policy) if i["level"] == "error"], [])

    def test_lint_flags_bad_policies(self):
        cfg = json.loads(DEFAULT_GUARD_POLICY.read_text())
        cfg["tools"] = {"*": "ALLOW", "Bash": "DENY"}
        cfg["unknown_tool"] = "ALLOW"
        cfg["network"]["allowed_hosts"].append("*")
        cfg["paths"]["secret_patterns"] = []
        checks = {(i["check"], i["level"]) for i in lint(GuardPolicy(cfg))}
        self.assertIn(("shadowed", "warn"), checks)
        self.assertIn(("overbroad", "error"), checks)


if __name__ == "__main__":
    unittest.main()
