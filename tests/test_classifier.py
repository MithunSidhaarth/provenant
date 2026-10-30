"""Optional model assistance: it can only escalate ALLOW, never authorizes, and leaks nothing."""
import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path

from agentshield import classifier
from agentshield.guard import Guard, GuardCall, GuardPolicy, Store, DEFAULT_GUARD_POLICY
from agentshield.models import Decision

SECRET = "AKIA" + "ABCDEFGHIJKLMNOP"


class FakeResp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def opener_returning(content, calls=None):
    def _open(req, timeout=None):
        if calls is not None:
            calls.append(json.loads(req.data))
        if isinstance(content, Exception):
            raise content
        return FakeResp(json.dumps({"choices": [{"message": {"content": content}}]}).encode())
    return _open


def advice(level="high", review=True):
    return json.dumps({"risk_level": level, "category": "exfiltration", "review_recommended": review,
                       "reason_codes": ["sends_data_external"]})


class ModelAssist(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.ws = str(self.home / "ws")
        os.makedirs(self.ws)
        self.sent = []

    def tearDown(self):
        self.tmp.cleanup()

    def guard(self, content, assist=None, cfg=None):
        policy_cfg = json.loads(Path(DEFAULT_GUARD_POLICY).read_text())
        if assist is not None:
            policy_cfg["model_assist"] = assist
        g = Guard(policy=GuardPolicy(policy_cfg), store=Store(self.home / ".provenant"))
        g._classifier = classifier.RemoteClassifier({"endpoint": "https://m.example/v1/chat/completions", "retries": 1,
                                                     "timeout_s": 0.2, **(cfg or {})},
                                                    opener=opener_returning(content, self.sent))
        g._classifier_error = None
        return g

    def check(self, g, tool, args):
        return g.check(GuardCall(tool, args, "s1", self.ws, "claude-code"), hold=False)

    def test_deny_stays_deny_and_model_not_called(self):
        g = self.guard(advice("low", False), {"escalate_on": ["high"]})
        self.assertEqual(self.check(g, "Bash", {"command": "rm -rf ~"}).decision, Decision.DENY)
        self.assertEqual(self.sent, [])

    def test_approval_cannot_become_allow(self):
        g = self.guard(advice("low", False), {"escalate_on": ["high"]})
        self.assertEqual(self.check(g, "Bash", {"command": "npm publish"}).decision, Decision.REQUIRE_APPROVAL)
        self.assertEqual(self.sent, [])

    def test_escalation_requires_policy_opt_in(self):
        g = self.guard(advice("high"))                       # no model_assist block: advisory only
        self.assertEqual(self.check(g, "WebFetch", {"url": "https://example.com"}).decision, Decision.ALLOW)
        self.assertEqual(len(self.sent), 1)
        g = self.guard(advice("high"), {"escalate_on": ["high", "critical"]})
        v = self.check(g, "WebFetch", {"url": "https://example.com"})
        self.assertEqual(v.decision, Decision.REQUIRE_APPROVAL)
        self.assertIsNone(v.grant_id)
        self.assertTrue(any("model-assisted" in r for r in v.reasons))

    def test_read_only_calls_skip_inference(self):
        g = self.guard(advice("critical"), {"escalate_on": ["critical"]})
        p = Path(self.ws) / "a.txt"
        p.write_text("x")
        self.assertEqual(self.check(g, "Read", {"file_path": str(p)}).decision, Decision.ALLOW)
        self.assertEqual(self.sent, [])

    def test_malformed_and_outage_never_authorize(self):
        for bad in ("not json", json.dumps({"risk_level": "none"}), json.dumps({**json.loads(advice()), "allow": True}),
                    urllib.error.URLError("down"), TimeoutError()):
            g = self.guard(bad, {"escalate_on": ["high"], "on_error": "require_approval"})
            self.assertEqual(self.check(g, "WebFetch", {"url": "https://example.com"}).decision,
                             Decision.REQUIRE_APPROVAL, bad)
            g = self.guard(bad, {"escalate_on": ["high"]})    # default: the deterministic ALLOW stands, nothing more
            self.assertEqual(self.check(g, "WebFetch", {"url": "https://example.com"}).decision, Decision.ALLOW)

    def test_bounded_retries(self):
        n = []
        clf = classifier.RemoteClassifier({"endpoint": "https://m.example/x", "retries": 2, "timeout_s": 0.2},
                                          opener=lambda req, timeout=None: n.append(1) or (_ for _ in ()).throw(OSError()))
        with self.assertRaises(classifier.ClassifierError):
            clf.classify({"tool": "x"})
        self.assertEqual(len(n), 3)

    def test_secrets_redacted_before_inference_and_absent_from_audit(self):
        g = self.guard(advice("medium", False), {"escalate_on": ["high"]})
        os.environ["PROVENANT_MODEL_API_KEY"] = "sk-test-not-real-123"
        try:
            v = self.check(g, "WebFetch", {"url": "https://example.com/docs"})
        finally:
            del os.environ["PROVENANT_MODEL_API_KEY"]
        self.assertEqual(v.decision, Decision.ALLOW)
        self.assertEqual(len(self.sent), 1)
        # the policy itself blocks most secret-bearing calls before the model; the payload builder redacts anyway
        payload = classifier.minimal_payload("Write", {"content": f"key={SECRET}"}, "write", "redacted", 1500)
        self.assertNotIn(SECRET, json.dumps(payload))
        self.assertIn("REDACTED", json.dumps(payload))
        log = (self.home / ".provenant" / "audit.jsonl").read_text()
        self.assertNotIn(SECRET, log)
        self.assertNotIn("sk-test-not-real-123", log)
        self.assertIn("model_advice", log)

    def test_metadata_mode_sends_no_values(self):
        p = classifier.minimal_payload("Bash", {"command": "cat notes.txt"}, "shell", "metadata", 1500)
        self.assertNotIn("notes.txt", json.dumps(p))

    def test_evaluated_args_are_executed_args(self):
        g = self.guard(advice("low", False), {"escalate_on": ["high"]})
        call = GuardCall("WebFetch", {"url": "https://example.com"}, "s1", self.ws, "claude-code")
        v = g.check(call, hold=False)
        other = GuardCall("WebFetch", {"url": "https://evil.example"}, "s1", self.ws, "claude-code", call.call_id)
        self.assertFalse(g.redeem(v, other))
        self.assertTrue(g.redeem(v, call))
        self.assertFalse(g.redeem(v, call))                  # single use

    def test_config_validation(self):
        h = self.home / "cfg"
        h.mkdir()
        self.assertFalse(classifier.load(h)[0].enabled)       # no file: off
        for cfg, msg in (({"enabled": True, "endpoint": "http://m.example/x"}, "https"),
                         ({"enabled": True, "endpoint": "https://m.example/x", "api_key": "x"}, "environment"),
                         ({"enabled": True, "endpoint": "https://m.example/x", "send": "everything"}, "send")):
            (h / "model.json").write_text(json.dumps(cfg))
            clf, err = classifier.load(h)
            self.assertFalse(clf.enabled)
            self.assertIn(msg, err)
        (h / "model.json").write_text(json.dumps({"enabled": True, "endpoint": "http://localhost:11434/v1/chat/completions"}))
        self.assertTrue(classifier.load(h)[0].enabled)


if __name__ == "__main__":
    unittest.main()
