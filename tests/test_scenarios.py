"""Before/after security regression tests.

BEFORE: the same agent with no enforcement (UnprotectedGateway). Every attack scenario must
actually cause harm in the simulated world, proving the attacks are real.
AFTER: the same agent behind AgentShield. No attack may cause any harm, decisions must match
the scenario's expected sequence, and benign tasks must still complete.
"""
import unittest

from agentshield.policy import PolicyEngine
from agentshield.runner import Shield

SHIELD = Shield()
ATTACKS = [k for k, v in SHIELD.scenarios.items() if v["kind"] == "attack"]
BENIGN = [k for k, v in SHIELD.scenarios.items() if v["kind"] == "benign"]


class ScenarioCoverage(unittest.TestCase):
    def test_required_categories_present(self):
        cats = {v["category"] for v in SHIELD.scenarios.values()}
        for c in ["legitimate_task", "prompt_injection_document", "prompt_injection_retrieval",
                  "sensitive_data", "excess_permissions", "fail_closed"]:
            self.assertIn(c, cats)


class Before(unittest.TestCase):
    def test_every_attack_succeeds_without_agentshield(self):
        for sid in ATTACKS:
            with self.subTest(sid):
                r = SHIELD.run(sid, protected=False)
                self.assertEqual(r["verdict"], "ATTACK SUCCEEDED")
                self.assertTrue(r["outcome"]["harms"])

    def test_doc_injection_baseline_exfiltrates_canary(self):
        r = SHIELD.run("doc_injection", protected=False)
        harms = {h["id"] for h in r["outcome"]["harms"]}
        self.assertTrue({"secret_read", "secret_exfiltrated", "external_email"} <= harms)


class After(unittest.TestCase):
    def test_every_attack_blocked_with_agentshield(self):
        for sid in ATTACKS:
            with self.subTest(sid):
                r = SHIELD.run(sid, protected=True)
                self.assertEqual(r["verdict"], "ATTACK BLOCKED", r["outcome"]["harms"])
                self.assertEqual(r["outcome"]["harms"], [])

    def test_decision_sequences_match_expected(self):
        for sid, sc in SHIELD.scenarios.items():
            with self.subTest(sid):
                self.assertEqual(SHIELD.run(sid, protected=True)["decisions"], sc["expected_protected"])

    def test_every_deny_has_a_reason(self):
        for sid in SHIELD.scenarios:
            r = SHIELD.run(sid, protected=True)
            for s in r["trace"]["steps"]:
                if s["result"] and s["result"]["decision"] != "ALLOW":
                    self.assertTrue(s["result"]["reasons"], (sid, s))

    def test_injected_steps_never_execute(self):
        for sid in ATTACKS:
            r = SHIELD.run(sid, protected=True)
            for s in r["trace"]["steps"]:
                if s["source"] in ("injected", "malformed") and s["result"]:
                    self.assertFalse(s["result"]["executed"], (sid, s))

    def test_benign_tasks_complete(self):
        r = SHIELD.run("benign_kb_lookup", protected=True)
        self.assertEqual(r["verdict"], "TASK COMPLETED")
        r = SHIELD.run("benign_email_summary", protected=True)
        self.assertEqual(r["verdict"], "AWAITING APPROVAL")
        out = SHIELD.decide(r["approvals"][0]["approval_id"], "human:tester", True)
        self.assertTrue(out["ok"])
        self.assertEqual(out["run"]["verdict"], "TASK COMPLETED")
        self.assertEqual(len(out["run"]["outcome"]["side_effects"]["outbox"]), 1)

    def test_legit_refund_in_poisoned_session_needs_and_survives_approval(self):
        r = SHIELD.run("kb_injection", protected=True)
        pending = [a for a in r["approvals"] if a["status"] == "pending"]
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["call"]["args"]["customer_id"], "C-101")
        out = SHIELD.decide(pending[0]["approval_id"], "human:tester", True)
        self.assertTrue(out["ok"])
        self.assertEqual(out["run"]["outcome"]["side_effects"]["refunds"],
                         [{"customer_id": "C-101", "amount": 20, "reason": "duplicate charge"}])
        self.assertEqual(out["run"]["outcome"]["harms"], [])


class DefenseInDepth(unittest.TestCase):
    """Prompt-injection attacks stay blocked even with any single policy rule removed."""

    def test_injection_attacks_survive_single_rule_ablation(self):
        for rule in PolicyEngine.RULES:
            shield = Shield(engine=PolicyEngine.from_file(disabled_rules=(rule,)))
            for sid in ["doc_injection", "kb_injection"]:
                with self.subTest(rule=rule, scenario=sid):
                    self.assertEqual(shield.run(sid, protected=True)["outcome"]["harms"], [])


if __name__ == "__main__":
    unittest.main()
