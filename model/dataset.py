"""Build, validate and split the labelled dataset for the optional risk classifier.

    python model/dataset.py build [--out model/data]      # from evals/attacks.json + evals/benign.json
    python model/dataset.py validate FILE.jsonl           # schema + leakage checks, exit 1 on any problem

Labels use the exact schema the runtime validates (agentshield/classifier.py), so a model trained here can be
plugged in without glue code. Splits are by *group* (attack family: category + tool + leading command word),
never by row, so near-duplicate variants of one attack cannot sit in both train and test.
Seed sources are synthetic: secrets appear only as {{fake:NAME}} placeholders, never as real values.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from agentshield.classifier import CATEGORIES, REASON_CODES, RISK_LEVELS, minimal_payload, validate  # noqa: E402

FAMILY = {  # eval category -> (classifier category, reason codes)
    "shell": ("destructive", ["deletes_data"]), "path": ("credential_access", ["touches_credentials"]),
    "ssrf": ("exfiltration", ["unusual_destination"]), "dlp": ("exfiltration", ["sends_data_external"]),
    "tamper": ("privilege_escalation", ["modifies_system_config"]), "rce": ("persistence", ["obfuscated_payload"]),
    "taint": ("prompt_injection_followthrough", ["untrusted_instruction"]), "classify": ("other", ["none"]),
    "failclosed": ("other", ["none"]),
}
SPLITS = (("train", 0.7), ("val", 0.15), ("test", 0.15))


def label(row: dict) -> dict:
    if row.get("expected") == "ALLOW":
        return {"risk_level": "low", "category": "benign", "review_recommended": False, "reason_codes": ["none"]}
    cat, codes = FAMILY.get(row.get("category"), ("other", ["none"]))
    deny = row.get("expected") == "DENY"
    risk = "critical" if deny and cat in ("destructive", "credential_access", "persistence") else "high" if deny else "medium"
    return {"risk_level": risk, "category": cat, "review_recommended": True, "reason_codes": codes}


def group_of(row: dict) -> str:
    args = row.get("args") or {}
    first = next((str(v) for v in args.values() if isinstance(v, str)), "") if isinstance(args, dict) else ""
    lead = first.strip().split(" ", 1)[0].lower()[:40]
    return hashlib.sha256(f"{row.get('category')}|{row.get('tool')}|{lead}".encode()).hexdigest()[:12]


def split_of(group: str) -> str:
    x = int(group[:8], 16) / 0xFFFFFFFF
    acc = 0.0
    for name, frac in SPLITS:
        acc += frac
        if x <= acc:
            return name
    return SPLITS[-1][0]


_POLICY = None


def runtime_category(tool, args) -> str:
    """The policy category the runtime sends with each call, so training inputs match production inputs."""
    global _POLICY
    if _POLICY is None:
        from agentshield.guard import GuardPolicy, DEFAULT_GUARD_POLICY
        _POLICY = GuardPolicy.from_file(DEFAULT_GUARD_POLICY)
    try:
        return _POLICY.effective_category(tool, args)
    except Exception:                                       # noqa: BLE001
        return "other"


def example(row: dict) -> dict:
    return {"id": row["id"], "group": group_of(row),
            "input": minimal_payload(row["tool"], row.get("args", {}), runtime_category(row["tool"], row.get("args", {})),
                                     "redacted", 1500),
            "label": label(row), "source": "evals/" + ("benign" if row.get("expected") == "ALLOW" else "attacks")}


def validate_rows(rows: list[dict]) -> list[str]:
    errs, seen, groups = [], set(), {}
    for i, r in enumerate(rows):
        try:
            validate(r["label"])
        except Exception as exc:                            # noqa: BLE001
            errs.append(f"row {i} ({r.get('id')}): bad label: {exc}")
        if r.get("id") in seen:
            errs.append(f"row {i}: duplicate id {r.get('id')}")
        seen.add(r.get("id"))
        groups.setdefault(r.get("group"), set()).add(r.get("split"))
        text = json.dumps(r.get("input"))
        if re.search(r"AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY", text):
            errs.append(f"row {i}: input looks like it contains a real credential")
    errs += [f"group {g} appears in several splits {sorted(s)}" for g, s in groups.items() if len(s) > 1]
    return errs


def build(out: Path) -> dict:
    rows = json.loads((ROOT / "evals/attacks.json").read_text()) + json.loads((ROOT / "evals/benign.json").read_text())
    data = [{**example(r)} for r in rows]
    for d in data:
        d["split"] = split_of(d["group"])
    errs = validate_rows(data)
    if errs:
        raise SystemExit("\n".join(errs))
    out.mkdir(parents=True, exist_ok=True)
    counts = {}
    for name, _ in SPLITS:
        part = [d for d in data if d["split"] == name]
        (out / f"{name}.jsonl").write_text("".join(json.dumps(d, ensure_ascii=False) + "\n" for d in part), encoding="utf-8")
        counts[name] = len(part)
    return {"rows": len(data), "splits": counts, "groups": len({d["group"] for d in data}),
            "labels": {"risk_levels": list(RISK_LEVELS), "categories": list(CATEGORIES), "reason_codes": list(REASON_CODES)}}


def main(argv: list[str]) -> int:
    if argv[:1] == ["build"]:
        out = Path(argv[argv.index("--out") + 1]) if "--out" in argv else ROOT / "model" / "data"
        print(json.dumps(build(out), indent=1))
        return 0
    if argv[:1] == ["validate"] and len(argv) > 1:
        rows = [json.loads(l) for p in argv[1:] for l in Path(p).read_text(encoding="utf-8").splitlines() if l.strip()]
        errs = validate_rows(rows)
        print("\n".join(errs) or f"ok: {len(rows)} rows")
        return 1 if errs else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
