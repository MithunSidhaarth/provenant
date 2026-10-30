"""Tamper-evidence tests for the audit chain."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from agentshield.audit import AuditLog
from agentshield.models import canonical_json, sha256_hex
from agentshield.runner import Shield
from agentshield.sandbox import VAULT


def populated():
    s = Shield()
    s.run("doc_injection", protected=True)
    s.run("kb_injection", protected=True)
    return s.audit


class AuditChain(unittest.TestCase):
    def test_clean_chain_verifies(self):
        a = populated()
        self.assertGreater(len(a.entries), 10)
        self.assertTrue(a.verify()["ok"])

    def test_records_inputs_decisions_reasons_outcomes_timestamps(self):
        a = populated()
        events = {e["event"] for e in a.entries}
        self.assertTrue({"session_start", "tool_request", "policy_decision", "tool_result",
                         "approval_requested"} <= events)
        dec = next(e for e in a.entries if e["event"] == "policy_decision" and e["data"]["decision"] == "DENY")
        self.assertTrue(dec["data"]["reasons"])
        self.assertTrue(all(e["ts"] for e in a.entries))

    def test_modified_entry_detected(self):
        a = populated()
        bad = copy.deepcopy(a.entries)
        k = next(i for i, e in enumerate(bad) if e["event"] == "policy_decision" and e["data"]["decision"] == "DENY")
        bad[k]["data"]["decision"] = "ALLOW"
        r = a.verify(bad)
        self.assertFalse(r["ok"])
        self.assertEqual(r["first_bad_seq"], k)

    def test_deleted_entry_detected(self):
        a = populated()
        bad = copy.deepcopy(a.entries)
        del bad[5]
        self.assertFalse(a.verify(bad)["ok"])

    def test_reordered_entries_detected(self):
        a = populated()
        bad = copy.deepcopy(a.entries)
        bad[3], bad[4] = bad[4], bad[3]
        self.assertFalse(a.verify(bad)["ok"])

    def test_truncation_of_tail_is_visible_via_head(self):
        a = populated()
        full = a.verify()
        cut = a.verify(a.entries[:-3])
        self.assertTrue(cut["ok"])          # a prefix is a valid chain...
        self.assertNotEqual(cut["head"], full["head"])  # ...but its head hash no longer matches the anchor

    def test_recomputed_chain_without_key_detected(self):
        a = populated()
        bad = copy.deepcopy(a.entries)
        bad[2]["data"]["note"] = "forged"
        prev = bad[1]["hash"]
        for e in bad[2:]:     # attacker rewrites every hash after the edit, but has no MAC key
            e["prev_hash"] = prev
            e["hash"] = sha256_hex(canonical_json({k: v for k, v in e.items() if k not in ("hash", "mac")}))
            prev = e["hash"]
        r = a.verify(bad)
        self.assertFalse(r["ok"])
        self.assertIn("MAC", r["problem"])

    def test_secrets_are_redacted_in_log(self):
        s = Shield()
        s.run("doc_injection", protected=False)   # baseline really leaks the canary
        blob = json.dumps(s.audit.entries)
        for v in VAULT.values():
            self.assertNotIn(v, blob)
        self.assertIn("[REDACTED:PROD_DB_PASSWORD", blob)

    def test_persisted_log_reloads_and_verifies(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "audit.jsonl"
            a = AuditLog(p, key=b"k" * 32)
            a.append("x", "s", {"n": 1})
            a.append("y", "s", {"n": 2})
            b = AuditLog(p, key=b"k" * 32)
            self.assertTrue(b.verify()["ok"])
            lines = p.read_text().splitlines()
            lines[0] = lines[0].replace('"n": 1', '"n": 9')
            p.write_text("\n".join(lines) + "\n")
            self.assertFalse(AuditLog(p, key=b"k" * 32).verify()["ok"])


if __name__ == "__main__":
    unittest.main()
