"""Score a risk classifier on the held-out split. Reports only what it measured.

    python model/evaluate.py --predictions preds.jsonl [--split model/data/test.jsonl]
    python model/evaluate.py --endpoint-from-config [--split ...]   # calls the model in ~/.provenant/model.json

preds.jsonl rows: {"id": ..., "prediction": {risk_level, category, review_recommended, reason_codes}}
A prediction that fails the runtime schema counts as an invalid output (the runtime treats it as a failure).
Key metric for Provenant: escalation recall (high/critical calls the model flags for review) and the false
escalation rate on benign calls (how often it would interrupt a human for nothing).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from agentshield.classifier import ClassifierError, validate  # noqa: E402


def score(rows: list[dict], preds: dict[str, dict | None]) -> dict:
    n = len(rows)
    invalid = rl_ok = cat_ok = 0
    risky = flagged_risky = benign = flagged_benign = 0
    for r in rows:
        gold, raw = r["label"], preds.get(r["id"])
        try:
            p = validate(raw).to_dict() if raw is not None else None
        except ClassifierError:
            p = None
        if p is None:
            invalid += 1
        rl_ok += bool(p and p["risk_level"] == gold["risk_level"])
        cat_ok += bool(p and p["category"] == gold["category"])
        if gold["risk_level"] in ("high", "critical"):
            risky += 1
            flagged_risky += bool(p and (p["review_recommended"] or p["risk_level"] in ("high", "critical")))
        if gold["category"] == "benign":
            benign += 1
            flagged_benign += bool(p and (p["review_recommended"] or p["risk_level"] in ("high", "critical")))
    return {"examples": n, "invalid_outputs": invalid,
            "risk_level_accuracy": round(rl_ok / n, 4) if n else None,
            "category_accuracy": round(cat_ok / n, 4) if n else None,
            "escalation_recall": round(flagged_risky / risky, 4) if risky else None,
            "false_escalation_rate": round(flagged_benign / benign, 4) if benign else None}


def main(argv: list[str]) -> int:
    split = Path(argv[argv.index("--split") + 1]) if "--split" in argv else ROOT / "model/data/test.jsonl"
    rows = [json.loads(l) for l in split.read_text(encoding="utf-8").splitlines() if l.strip()]
    if "--predictions" in argv:
        p = Path(argv[argv.index("--predictions") + 1])
        preds = {d["id"]: d.get("prediction") for d in map(json.loads, p.read_text(encoding="utf-8").splitlines()) if d}
    elif "--endpoint-from-config" in argv:
        from agentshield import classifier
        from agentshield.guard import provenant_home
        clf, err = classifier.load(provenant_home())
        if err or not clf.enabled:
            print(json.dumps({"error": err or "model assistance is not enabled"}))
            return 1
        preds = {}
        for r in rows:
            try:
                preds[r["id"]] = clf.classify(r["input"]).to_dict()
            except ClassifierError:
                preds[r["id"]] = None
    else:
        print(__doc__)
        return 2
    print(json.dumps({"split": str(split), **score(rows, preds)}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
