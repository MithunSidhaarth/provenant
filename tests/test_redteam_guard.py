"""Regression tests for the 100+ attack red-team catalogue against the REAL-tool guard.

These lock in the hardening from the guard red-team pass: every catalogued attack must be contained
(blocked or held), and every benign call must stay allowed so the hardening added no false positives.
"""
import tempfile
import unittest

from agentshield.guard import Guard, GuardCall, GuardPolicy, Store
from agentshield.redteam_guard import ATTACKS, BENIGN, RANK, run_suite


class RedTeamGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.guard = Guard(GuardPolicy.from_file(), Store(cls.tmp))
        cls.rep = run_suite(cls.guard)

    def _decide(self, atk):
        session = self.guard.store.load_session("t")
        session.update(atk.session)
        return self.guard.policy.evaluate(GuardCall(atk.tool, atk.args, "t", atk.workspace), session).decision

    def test_catalogue_is_at_least_100_attacks(self):
        self.assertGreaterEqual(len(ATTACKS), 100)

    def test_every_attack_is_contained(self):
        # A single list is the whole report: any entry here is an attack that got through.
        self.assertEqual(self.rep["through"], [], f"{len(self.rep['through'])} attack(s) got through")
        self.assertEqual(self.rep["safe"], self.rep["total"])

    def test_every_persona_fully_contained(self):
        for p in self.rep["personas"]:
            self.assertEqual(p["safe"], p["total"], p["persona"])

    def test_the_hard_bypasses_are_denied_not_merely_held(self):
        from agentshield.guard import DENY
        must_deny = {"sh_rm_split_flags", "sh_rm_long", "sh_rm_interspersed", "sh_find_delete_root",
                     "sh_dev_redir", "sh_shred_disk", "win_remove_item_alias", "path_proc_environ_sh",
                     "ssrf_decimal", "ssrf_hex", "ssrf_octal", "ssrf_dotted_hex", "ssrf_ipv6_mapped",
                     "cls_get_shell", "cls_list_run", "cls_query_cmd", "dlp_split_key"}
        for atk in ATTACKS:
            if atk.id in must_deny:
                self.assertEqual(self._decide(atk), DENY, atk.id)

    def test_no_false_positives_on_benign_calls(self):
        over = [(a.id, a.expect.value, self._decide(a).value) for a in BENIGN
                if RANK[self._decide(a)] > RANK[a.expect]]
        self.assertEqual(over, [], f"benign calls over-blocked: {over}")

    def test_audit_chain_survives_the_campaign(self):
        self.assertTrue(self.guard.audit.verify()["ok"])


if __name__ == "__main__":
    unittest.main()
