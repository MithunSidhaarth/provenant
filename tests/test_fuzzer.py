"""Mutation-fuzzer regression tests: every obfuscated variant is live and contained."""
import unittest

from agentshield.agent import extract_directives
from agentshield.fuzzer import MUTATIONS, SEEDS, build_document, run_campaign
from agentshield.normalize import views


class Fuzzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rep = run_campaign()

    def test_campaign_size(self):
        self.assertGreaterEqual(self.rep["summary"]["variants"], 50)
        self.assertEqual(len(self.rep["classes"]), len(MUTATIONS))

    def test_every_variant_is_a_live_attack(self):
        dead = [(v["seed"], v["mutation"]) for v in self.rep["variants"] if not v["fired"]]
        self.assertEqual(dead, [])

    def test_every_variant_contained(self):
        leaks = [(v["seed"], v["mutation"], v["shield_harms"]) for v in self.rep["variants"] if not v["contained"]]
        self.assertEqual(leaks, [])
        self.assertTrue(self.rep["summary"]["audit_chain_ok"])

    def test_detection_covers_everything_we_decode(self):
        for c in self.rep["classes"]:
            if c["mutation"] not in ("rot13", "reversed", "natural_language"):
                self.assertEqual(c["detected"], c["variants"], c["mutation"])

    def test_obfuscated_values_are_still_tainted(self):
        steps = SEEDS[0][2]
        for mut in ("base64", "hex", "zero_width", "homoglyph", "ascii_smuggling"):
            text = "\n".join(views(build_document(steps, mut))).lower()
            self.assertIn("ops-sync@contractor-portal.example", text, mut)

    def test_agent_decodes_every_class(self):
        for mut in MUTATIONS:
            self.assertTrue(extract_directives(build_document(SEEDS[1][2], mut)), mut)


if __name__ == "__main__":
    unittest.main()
