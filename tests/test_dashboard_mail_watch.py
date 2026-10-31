"""Dashboard-started inbox watch (mailwatch.py + /api/mail/watch). Fake IMAP and fake caller: no network, no calls."""
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from agentshield import mailwatch, server
from email.message import EmailMessage

from tests.test_mail_watch import PHISH, FakeImap, _raw


def _plain(sender, subject, body):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"], msg["Message-ID"] = sender, "me@example.com", subject, f"<{subject}@t.example>"
    msg.set_content(body)
    return msg.as_bytes()


BENIGN = _plain("Asha <asha@team.example>", "Lunch on Friday?", "Are you free for lunch on Friday at 1?")


def _phish(n):
    return _raw("Microsoft Account Team <security@micros0ft-verify.example>", f"URGENT {n}: verify your account within 24 hours",
                "Unusual sign-in. Confirm your password here: https://bit.ly/x", reply_to="collect@login-check.example")


def _wait(cond, seconds=5.0):
    end = time.time() + seconds
    while time.time() < end and not cond():
        time.sleep(0.02)
    return cond()


class FakeRw:
    def __init__(self):
        self.moved = []

    def uid(self, command, *args):
        assert command == "MOVE", command
        self.moved.append((int(args[0]), args[1]))
        return "OK", [b""]

    def logout(self):
        pass


class Harness:
    def __init__(self, imap, polls=4, ready=True, level="high", max_calls=5, result=None):
        self.imap, self.audit, self.tasks, self.n = imap, [], [], 0
        self.rw = FakeRw()
        self.result = result or {"status": "completed", "execution_id": "exec-1", "transcript": "assistant: hello\nuser: ok"}
        def sleep(_):
            self.n += 1
            time.sleep(0.01)
            if self.n >= polls:
                self.w._stop.set()
        def caller(task):
            self.tasks.append(task)
            r = dict(self.result)
            if callable(r.get("transcript")):
                r["transcript"] = r["transcript"](task)
            return r
        self.w = mailwatch.MailWatcher(audit=lambda ev, sid, data: self.audit.append((ev, sid, data)),
                                       connect=lambda h, u, p: imap, credentials=lambda: ("imap.test", "me@example.com", "pw"),
                                       caller=caller, ready=lambda: ready, level=lambda: level, interval=5,
                                       max_calls_per_hour=max_calls, sleep=sleep, open_rw=lambda: self.rw)

    def run(self):
        self.w.start()
        assert _wait(lambda: not self.w._thread.is_alive())
        return self.w.status()


class MailWatcherTests(unittest.TestCase):
    def test_not_configured_starts_nothing(self):
        w = mailwatch.MailWatcher(credentials=lambda: None)
        st = w.start()
        self.assertEqual(st["state"], "not_configured")
        self.assertFalse(st["running"])
        self.assertIsNone(w._thread)

    def test_only_new_mail_is_scanned_and_suspicious_mail_rings_once(self):
        imap = FakeImap({1: PHISH})                      # already in the inbox when the dashboard opened: ignored
        imap.pending = {2: {2: BENIGN}, 3: {3: _phish(3)}}
        h = Harness(imap)
        st = h.run()
        self.assertNotIn(1, imap.fetched)
        self.assertEqual(st["scanned"], 2)
        self.assertEqual(st["flagged"], 1)
        flagged = [m for m in st["mails"] if m["level"] != "low"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0]["level"], "high")
        self.assertTrue(_wait(lambda: len(h.tasks) == 1))
        self.assertTrue(_wait(lambda: flagged[0]["call"]["status"] == "completed"))
        task = h.tasks[0]
        self.assertIn("high-risk email", task)
        self.assertNotIn("ignore previous instructions", task.lower())
        self.assertNotIn("bit.ly", task)

    def test_audit_never_holds_the_body(self):
        imap = FakeImap({})
        imap.pending = {1: {1: PHISH}}
        h = Harness(imap, polls=2)
        h.run()
        _wait(lambda: any(e[0] == "mail_phone_alert" for e in h.audit))
        blob = json.dumps(h.audit).lower()
        self.assertIn("mail_verdict", blob)
        self.assertNotIn("ignore previous instructions", blob)
        self.assertNotIn("bit.ly", blob)
        self.assertNotIn("pw", [str(e[2].get("account")) for e in h.audit])

    def test_no_call_without_phone_and_call_cap(self):
        imap = FakeImap({})
        imap.pending = {1: {1: PHISH}}
        h = Harness(imap, polls=2, ready=False)
        st = h.run()
        self.assertEqual(st["mails"][0]["call"]["status"], "not_configured")
        self.assertEqual(h.tasks, [])

        imap = FakeImap({})
        imap.pending = {1: {i: _phish(i) for i in range(1, 4)}}
        h = Harness(imap, polls=2, max_calls=2)
        st = h.run()
        statuses = sorted(str(m["call"]["status"]) for m in st["mails"])
        self.assertEqual(statuses.count("skipped"), 1)
        self.assertTrue(_wait(lambda: len(h.tasks) == 2))

    def test_medium_level_rings_for_medium(self):
        imap = FakeImap({})
        imap.pending = {1: {1: BENIGN}}
        h = Harness(imap, polls=2, level="medium")
        st = h.run()
        self.assertEqual(st["mails"][0]["level"], "low")
        self.assertIsNone(st["mails"][0]["call"])

    def test_stop_ends_the_thread(self):
        imap = FakeImap({})
        w = mailwatch.MailWatcher(connect=lambda h, u, p: imap, credentials=lambda: ("h", "me@example.com", "pw"),
                                  ready=lambda: False, level=lambda: "high", interval=0.05)
        w.start()
        self.assertTrue(_wait(lambda: w.state["state"] == "watching"))
        st = w.stop()
        self.assertFalse(st["running"])
        self.assertFalse(w._thread.is_alive())

    def test_reconnects_after_a_dropped_connection(self):
        good = FakeImap({})
        good.pending = {1: {1: PHISH}}
        calls = {"n": 0}
        def connect(h, u, p):
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("network down")
            return good
        h = Harness(good, polls=3)
        h.w._connect = connect
        st = h.run()
        self.assertGreaterEqual(calls["n"], 2)
        self.assertEqual(len(st["mails"]), 1)        # mail that arrived after the reconnect is still scanned


class KeepOrTrashTests(unittest.TestCase):
    def _one_phish(self, **kw):
        imap = FakeImap({})
        imap.pending = {1: {7: _phish(1)}}
        h = Harness(imap, polls=2, **kw)
        st = h.run()
        self.assertTrue(_wait(lambda: st["mails"][0]["call"].get("outcome") is not None))
        return h, st["mails"][0]["call"]

    def test_saying_the_code_keeps_the_mail(self):
        import re
        said = lambda task: "assistant: say the code\nuser: " + " ".join(re.search(r"say the code ((?:\d ){3}\d)", task).group(1).split())
        h, call = self._one_phish(result={"status": "completed", "execution_id": "e", "transcript": said})
        self.assertTrue(call["outcome"].startswith("kept"), call)
        self.assertEqual(h.rw.moved, [])
        self.assertIn("Ivy from Provenant", h.tasks[0])

    def test_no_code_moves_it_to_trash_not_delete(self):
        h, call = self._one_phish()
        self.assertTrue(call["outcome"].startswith("moved to Trash"), call)
        self.assertEqual(h.rw.moved, [(7, '"[Gmail]/Trash"')])
        self.assertTrue(any(e[0] == "mail_trashed_by_phone" for e in h.audit))

    def test_unanswered_call_also_trashes(self):
        h, call = self._one_phish(result={"status": "no-answer", "execution_id": "e"})
        self.assertTrue(call["outcome"].startswith("moved to Trash"), call)

    def test_failed_call_leaves_the_mail(self):
        h, call = self._one_phish(result={"status": "error", "error": "HTTP 401"})
        self.assertIn("left in inbox", call["outcome"])
        self.assertEqual(h.rw.moved, [])

    def test_code_said_by_ivy_only_does_not_count(self):
        import re
        ivy_only = lambda task: "assistant: the code is " + re.search(r"say the code ((?:\d ){3}\d)", task).group(1) + "\nuser: what?"
        h, call = self._one_phish(result={"status": "completed", "execution_id": "e", "transcript": ivy_only})
        self.assertTrue(call["outcome"].startswith("moved to Trash"), call)


class LiveConsoleTests(unittest.TestCase):
    def test_events_are_stamped_live_and_gate_runs_on_injection(self):
        imap = FakeImap({})
        imap.pending = {1: {1: PHISH}}
        h = Harness(imap, polls=2)
        seen = []
        h.w._gate = lambda v, target: seen.append(target) or {"tool": "send_email", "to": target, "decision": "DENY"}
        st = h.run()
        self.assertEqual(seen, ["collect@login-check.example"])
        self.assertEqual(st["mails"][0]["gate"]["decision"], "DENY")
        for ev, sid, data in h.audit:
            self.assertEqual((sid, data["source"], data["mode"]), ("mail-watch", "mail-watch", "live"))

    def test_real_guard_blocks_the_injected_send_and_console_counts_it(self):
        with tempfile.TemporaryDirectory() as home, patch.dict(os.environ, {"PROVENANT_HOME": home}):
            from agentshield import guard as guard_mod
            store = guard_mod.Store()
            imap = FakeImap({})
            imap.pending = {1: {1: PHISH}}
            h = Harness(imap, polls=2, ready=False)
            h.w._audit = lambda ev, sid, data: store.audit.append(ev, sid, data)
            h.w._gate = mailwatch.guard_gate
            st = h.run()
            self.assertEqual(st["mails"][0]["gate"]["decision"], "DENY")
            app = server.App(__import__("pathlib").Path(home) / "demo")
            stats = app.guard_log(0)["stats"]
            self.assertEqual(stats["mail_scanned"], 1)
            self.assertEqual(stats["mail_flagged"], 1)
            self.assertGreaterEqual(stats["tool_requests_observed"], 1)
            self.assertGreaterEqual(stats["blocked"], 1)
            self.assertGreaterEqual(stats["live_sessions"], 1)
            blob = json.dumps(store.audit.snapshot()).lower()
            self.assertNotIn("bit.ly", blob)                 # the body never reaches the audit chain


class MailWatchApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        imap = FakeImap({})
        self.watcher = mailwatch.MailWatcher(connect=lambda h, u, p: imap, credentials=lambda: ("h", "me@example.com", "pw"),
                                             ready=lambda: False, level=lambda: "high", interval=0.05)
        self.patch = patch.object(mailwatch, "shared", return_value=self.watcher)
        self.patch.start()
        self.httpd = server.serve("127.0.0.1", 0, audit_dir=__import__("pathlib").Path(self.tmp.name))
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.watcher.stop()
        self.httpd.shutdown(); self.httpd.server_close()
        self.patch.stop(); self.tmp.cleanup()

    def _post(self, body, header=True):
        req = urllib.request.Request(self.base + "/api/mail/watch", data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", **({"X-Provenant-Dashboard": "1"} if header else {})})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())

    def test_start_status_stop(self):
        st = self._post({"action": "start"})
        self.assertTrue(st["running"])
        self.assertEqual(st["account"], "me***@example.com")
        with urllib.request.urlopen(self.base + "/api/mail/watch", timeout=5) as r:
            got = json.loads(r.read())
        self.assertNotIn("pw", json.dumps(got).replace("phone_ready", ""))
        self.assertFalse(self._post({"action": "stop"})["running"])

    def test_cross_site_post_refused(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post({"action": "start"}, header=False)
        self.assertEqual(cm.exception.code, 403)
        self.assertFalse(self.watcher.state["running"])

    def test_bad_action(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post({"action": "delete"})
        self.assertEqual(cm.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
