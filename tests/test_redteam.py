"""The red-team loop finds the known detection gaps, proposes fixes, and the fixes verify."""
import unittest

from agentshield.redteam import replay, run


class RedTeam(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rep = run()

    def test_finds_the_blind_classes(self):
        self.assertEqual({f["mutation"] for f in self.rep["findings"]}, {"rot13", "reversed"})

    def test_proposals_close_the_gap_without_new_false_positives(self):
        for f in self.rep["findings"]:
            p = f["proposal"]
            self.assertEqual(p["class_detection_after"], "6/6")
            self.assertEqual(p["containment_after"], 100.0)
            self.assertLessEqual(p["benign_detection_fp_after"], p["benign_detection_fp_before"])
            self.assertEqual(p["benign_task_fp_after"], 0.0)
        self.assertEqual(self.rep["combined_patch"]["summary"]["detection_pct"], 100.0)

    def test_generated_regression_tests_pass(self):
        for f in self.rep["findings"]:
            ns = {}
            src = "class T:\n" + f["proposal"]["regression_test"]
            exec(compile(src, "<generated>", "exec"), {"replay": replay}, ns)
            name = next(n for n in vars(ns["T"]) if n.startswith("test_"))
            getattr(ns["T"], name)(self)   # runs the generated assertions with this TestCase

    def test_live_policy_is_not_modified(self):
        from agentshield.policy import PolicyEngine
        self.assertEqual(PolicyEngine.from_file().config["canonicalisation"]["extra_decoders"], [])


if __name__ == "__main__":
    unittest.main()
