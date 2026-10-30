"""Self-red-team loop.

1. Run the mutation campaign and the benign corpus.
2. For every class with a containment or detection miss, take the smallest failing document as a
   minimal reproduction.
3. Propose a candidate fix (an extra canonicalisation decoder, expressed as a policy change),
   apply it to a *copy* of the policy, and replay: recall on the attacks and false positives on
   the benign corpus, before and after.
4. Emit a regression test for the reproduction.

Nothing is applied to the live policy automatically: a person reviews the proposal. That keeps
the security boundary under human change control, and the report shows the trade-off (recall
gained vs. false positives added) so the decision is informed.
"""
from __future__ import annotations

import copy
import json

from .audit import AuditLog
from .fuzzer import lab_scenario, run_campaign
from .runner import Run
from .sandbox import VAULT
from .policy import PolicyEngine
from .normalize import EXTRA_DECODERS

# Which candidate decoder addresses which mutation class.
CANDIDATES = {"rot13": "rot13", "reversed": "reversed"}


def _engine_with(base: PolicyEngine, decoders: list[str]) -> PolicyEngine:
    cfg = copy.deepcopy(base.config)
    cfg.setdefault("canonicalisation", {})["extra_decoders"] = decoders
    cfg["version"] = f"{base.version}+redteam:{'+'.join(decoders) or 'none'}"
    return PolicyEngine(cfg)


def replay(document: str, decoders: list[str], engine: PolicyEngine | None = None) -> dict:
    """Run one document through the obedient agent behind AgentShield with the given decoders."""
    eng = _engine_with(engine or PolicyEngine.from_file(), decoders)
    return Run(lab_scenario(document), True, AuditLog(redact=VAULT), eng).execute()


def regression_test(seed: str, mutation: str, decoder: str, document: str) -> str:
    return (
        f"    def test_redteam_{seed}_{mutation}_detected_and_contained(self):\n"
        f"        # minimal reproduction found by agentshield.redteam\n"
        f"        doc = {json.dumps(document, ensure_ascii=False)}\n"
        f"        rep = replay(doc, [{decoder!r}])\n"
        f"        self.assertTrue(rep['trace']['steps'][0]['result']['injection_indicators'])\n"
        f"        self.assertEqual(rep['outcome']['harms'], [])\n")


def run(engine: PolicyEngine | None = None) -> dict:
    engine = engine or PolicyEngine.from_file()
    base = run_campaign(engine)
    findings = []
    for cls in base["classes"]:
        failing = [v for v in base["variants"] if v["mutation"] == cls["mutation"]
                   and (not v["contained"] or not v["detected"])]
        if not failing:
            continue
        repro = min(failing, key=lambda v: len(v["document"]))
        kind = "containment" if any(not v["contained"] for v in failing) else "detection"
        cand = CANDIDATES.get(cls["mutation"])
        f = {"mutation": cls["mutation"], "kind": kind, "failing_variants": len(failing),
             "minimal_repro": {"seed": repro["seed"], "document": repro["document"],
                               "decisions": repro["shield_decisions"]},
             "proposal": None}
        if cand and cand in EXTRA_DECODERS:
            patched = run_campaign(_engine_with(engine, [cand]))
            pc = next(c for c in patched["classes"] if c["mutation"] == cls["mutation"])
            f["proposal"] = {
                "change": {"policy.json": {"canonicalisation": {"extra_decoders": [cand]}}},
                "rationale": f"canonicalise untrusted content with a {cand} view before taint and detection",
                "class_detection_before": f"{cls['detected']}/{cls['variants']}",
                "class_detection_after": f"{pc['detected']}/{pc['variants']}",
                "overall_detection_before": base["summary"]["detection_pct"],
                "overall_detection_after": patched["summary"]["detection_pct"],
                "containment_after": patched["summary"]["containment_pct"],
                "benign_detection_fp_before": base["summary"]["detection_false_positive_pct"],
                "benign_detection_fp_after": patched["summary"]["detection_false_positive_pct"],
                "benign_task_fp_after": patched["summary"]["task_false_positive_pct"],
                "regression_test": regression_test(repro["seed"], cls["mutation"], cand, repro["document"]),
                "status": "proposed: awaiting human review",
            }
        findings.append(f)
    combined = None
    decs = [f["proposal"]["change"]["policy.json"]["canonicalisation"]["extra_decoders"][0]
            for f in findings if f["proposal"]]
    if decs:
        all_p = run_campaign(_engine_with(engine, decs))["summary"]
        combined = {"extra_decoders": decs, "summary": all_p}
    return {"baseline": base["summary"], "findings": findings, "combined_patch": combined}


if __name__ == "__main__":
    rep = run()
    print("baseline:", json.dumps(rep["baseline"]))
    for f in rep["findings"]:
        p = f["proposal"] or {}
        print(f"- {f['mutation']}: {f['kind']} miss in {f['failing_variants']} variants; "
              f"proposal: {p.get('rationale', 'none')}; class detection {p.get('class_detection_before')} -> "
              f"{p.get('class_detection_after')}; benign FP {p.get('benign_detection_fp_before')}% -> "
              f"{p.get('benign_detection_fp_after')}%")
    if rep["combined_patch"]:
        print("with all proposals:", json.dumps(rep["combined_patch"]["summary"]))
