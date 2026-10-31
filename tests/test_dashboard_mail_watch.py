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


class Harness:
    def __init__(self, imap, polls=4, ready=True, level="high", max_calls=5):
        self.imap, self.audit, self.tasks, self.n = imap, [], [], 0
        def sleep(_):
            self.n += 1
            time.sleep(0.01)
            if self.n >= polls:
                self.w._stop.set()
        def caller(task):
            self.tasks.append(task)
            return {"ok": True, "status": "completed", "execution_id": "exec-1"}
        self.w = mailwatch.MailWatcher(audit=lambda ev, sid, data: self.audit.append((ev, sid, data)),
                                       connect=lambda h, u, p: imap, credentials=lambda: ("imap.test", "me@example.com", "pw"),
                                       caller=caller, ready=lambda: ready, level=lambda: level, interval=5,
                                       max_calls_per_hour=max_calls, sleep=sleep)

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
        self.assertIn("suspicious email", task)
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
