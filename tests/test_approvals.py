"""Approval workflow and execution-grant tests: nothing high impact runs without a human."""
import unittest

from agentshield.models import Decision
from agentshield.tools import ExecutionGrant

from .helpers import AGENT, make_gateway, call

TASK = "Email manager@corp.example the summary and refund C-101 20"


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class Approvals(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.gw, self.world, self.audit = make_gateway(clock=self.clock)
        self.ctx = self.gw.open_session(AGENT, TASK)

    def request_email(self):
        res = self.gw.invoke(call(self.ctx, "send_email", to="manager@corp.example", subject="s", body="b"))
        self.assertEqual(res.decision, Decision.REQUIRE_APPROVAL)
        return res

    def test_pending_request_executes_nothing(self):
        res = self.request_email()
        self.assertFalse(res.executed)
        self.assertEqual(self.world.outbox, [])
        self.assertEqual(len(self.gw.pending()), 1)

    def test_human_approval_executes_exactly_once(self):
        res = self.request_email()
        out = self.gw.decide(res.approval_id, "human:mithun", True)
        self.assertTrue(out["ok"], out)
        self.assertEqual(len(self.world.outbox), 1)
        again = self.gw.decide(res.approval_id, "human:mithun", True)
        self.assertFalse(again["ok"])
        self.assertEqual(len(self.world.outbox), 1)

    def test_agent_cannot_approve(self):
        res = self.request_email()
        for who in [AGENT, "human:support-agent", "human:", "", None, "admin"]:
            self.assertFalse(self.gw.decide(res.approval_id, who, True)["ok"], who)
        self.assertEqual(self.world.outbox, [])

    def test_rejection_executes_nothing(self):
        res = self.request_email()
        out = self.gw.decide(res.approval_id, "human:mithun", False, "not now")
        self.assertEqual(out["status"], "rejected")
        self.assertFalse(self.gw.decide(res.approval_id, "human:mithun", True)["ok"])
        self.assertEqual(self.world.outbox, [])

    def test_expired_request_cannot_be_approved(self):
        res = self.request_email()
        self.clock.t += self.gw.approval_ttl + 1
        out = self.gw.decide(res.approval_id, "human:mithun", True)
        self.assertFalse(out["ok"])
        self.assertEqual(out["status"], "expired")
        self.assertEqual(self.world.outbox, [])

    def test_modified_call_voids_approval(self):
        res = self.request_email()
        self.gw.approvals[res.approval_id].call.args["to"] = "attacker@corp.example"
        self.assertFalse(self.gw.decide(res.approval_id, "human:mithun", True)["ok"])
        self.assertEqual(self.world.outbox, [])

    def test_approval_cannot_override_a_later_deny(self):
        res = self.gw.invoke(call(self.ctx, "issue_refund", customer_id="C-101", amount=20, reason="dup"))
        self.assertEqual(res.decision, Decision.REQUIRE_APPROVAL)
        self.gw.engine.config["refund_limit"] = 10      # policy tightened while the request waited
        try:
            out = self.gw.decide(res.approval_id, "human:mithun", True)
        finally:
            self.gw.engine.config["refund_limit"] = 100
        self.assertFalse(out["ok"])
        self.assertEqual(self.world.refunds, [])

    def test_unknown_approval_id(self):
        self.assertFalse(self.gw.decide("appr_nope", "human:mithun", True)["ok"])

    def test_decisions_are_audited(self):
        res = self.request_email()
        self.gw.decide(res.approval_id, AGENT, True)
        self.gw.decide(res.approval_id, "human:mithun", True)
        events = [e["event"] for e in self.audit.entries]
        for ev in ["approval_requested", "approval_refused", "approval_granted", "tool_result"]:
            self.assertIn(ev, events)
        self.assertTrue(self.audit.verify()["ok"])


class ExecutionGrants(unittest.TestCase):
    """Tools are unreachable without a gateway-minted, single-use, call-bound grant."""

    def setUp(self):
        self.gw, self.world, _ = make_gateway()
        self.ctx = self.gw.open_session(AGENT, "email manager@corp.example")
        self.c = call(self.ctx, "send_email", to="manager@corp.example", subject="s", body="b")

    def test_no_grant(self):
        with self.assertRaises(PermissionError):
            self.gw.registry.execute(None, self.c)

    def test_forged_grant(self):
        with self.assertRaises(PermissionError):
            self.gw.registry.execute(ExecutionGrant(self.c.fingerprint(), "n", "0" * 64), self.c)

    def test_grant_for_other_call(self):
        other = call(self.ctx, "read_document", doc_id="q3_onboarding")
        g = self.gw.registry.mint_grant(other.fingerprint())
        with self.assertRaises(PermissionError):
            self.gw.registry.execute(g, self.c)

    def test_grant_replay(self):
        g = self.gw.registry.mint_grant(self.c.fingerprint())
        self.gw.registry.execute(g, self.c)
        with self.assertRaises(PermissionError):
            self.gw.registry.execute(g, self.c)
        self.assertEqual(len(self.world.outbox), 1)


if __name__ == "__main__":
    unittest.main()


class RiskScoring(unittest.TestCase):
    def test_queue_is_sorted_riskiest_first_and_explained(self):
        from agentshield.runner import Shield
        s = Shield()
        s.run("benign_email_summary")
        s.run("kb_injection")
        q = s.pending_approvals()
        self.assertEqual([a["call"]["tool"] for a in q], ["issue_refund", "send_email"])
        self.assertGreater(q[0]["risk"]["score"], q[1]["risk"]["score"])
        self.assertIn("the session has read content with injection indicators", q[0]["risk"]["factors"])
