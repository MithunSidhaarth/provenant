"""Audit checkpoints, external anchoring and retention for the live guard.

Threat model. The local chain (hash links + HMAC) catches edits by anyone without the audit key. It cannot,
on its own, catch (a) someone truncating the tail, which leaves a valid shorter chain, or (b) a privileged
attacker who holds the key and rewrites the whole file. A checkpoint copies the current head (seq, hash) to a
location the attacker is assumed NOT to control, signed with a separate anchor key that lives there too:
a different disk, a mounted share, a synced folder, or a repository pushed elsewhere. Verification against
those checkpoints detects truncation and rewriting of anything at or before the last checkpoint. Entries
written after the last checkpoint have only the local guarantees. If the anchor location is also
compromised, nothing here helps; that is out of scope.

Retention. Deleting old lines would break the chain, so pruning works on a checkpoint boundary: the pruned
entries are exported to an archive file first, then the log keeps entries from the boundary on, and a
MAC-signed retention record (first_seq, prev_hash) tells the verifier where the chain now starts. The
archive plus the remaining log still verify end to end.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from .models import canonical_json


def _anchor_key(anchor_dir: Path) -> bytes:
    env = os.environ.get("PROVENANT_ANCHOR_KEY")
    if env:
        return env.encode()
    kf = anchor_dir / "anchor.key"
    if not kf.exists():
        anchor_dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(secrets.token_hex(32))
    return kf.read_text(encoding="utf-8").strip().encode()


def _sign(key: bytes, rec: dict) -> str:
    return hmac.new(key, canonical_json(rec).encode(), hashlib.sha256).hexdigest()


def checkpoint(guard, anchor_dir: Path | str) -> dict:
    """Verify the local chain, then record its head in the anchor directory (and in the state DB)."""
    anchor_dir = Path(anchor_dir).expanduser()
    if anchor_dir.resolve() == guard.store.home.resolve() or guard.store.home.resolve() in anchor_dir.resolve().parents:
        return {"ok": False, "reason": "the anchor must live outside the Provenant home it protects"}
    v = guard.audit.verify()
    if not v["ok"]:
        return {"ok": False, "reason": f"local chain is already broken at seq {v['first_bad_seq']}: {v['problem']}"}
    entries = guard.audit.snapshot()
    if not entries:
        return {"ok": False, "reason": "nothing to checkpoint"}
    rec = {"seq": entries[-1]["seq"], "head": entries[-1]["hash"], "ts": time.time(),
           "host_home": str(guard.store.home)}
    rec["sig"] = _sign(_anchor_key(anchor_dir), rec)
    with (anchor_dir / "checkpoints.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
    guard.store.db.add_checkpoint(rec["seq"], rec["head"], str(anchor_dir))
    guard.audit.append("audit_checkpoint", "provenant", {"seq": rec["seq"], "head": rec["head"]})
    return {"ok": True, **{k: rec[k] for k in ("seq", "head")}, "anchor": str(anchor_dir)}


def verify_against(guard, anchor_dir: Path | str) -> dict:
    """Local chain must verify AND contain every anchored head unchanged."""
    anchor_dir = Path(anchor_dir).expanduser()
    local = guard.audit.verify()
    if not local["ok"]:
        return {"ok": False, "problem": f"local chain broken at seq {local['first_bad_seq']}: {local['problem']}"}
    cp_file = anchor_dir / "checkpoints.jsonl"
    if not cp_file.exists():
        return {"ok": True, "checkpoints": 0, "note": "no external checkpoints yet; only local integrity was checked"}
    key = _anchor_key(anchor_dir)
    by_seq = {e["seq"]: e for e in guard.audit.snapshot()}
    first_kept = min(by_seq) if by_seq else 0
    last = None
    n = 0
    for line in cp_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        body = {k: v for k, v in rec.items() if k != "sig"}
        if not hmac.compare_digest(rec.get("sig", ""), _sign(key, body)):
            return {"ok": False, "problem": f"checkpoint at seq {rec.get('seq')} has an invalid signature"}
        n += 1
        last = rec
        if rec["seq"] < first_kept:
            continue                         # pruned under the retention policy; the archive holds it
        e = by_seq.get(rec["seq"])
        if e is None:
            return {"ok": False, "problem": f"log is truncated: anchored seq {rec['seq']} is missing"}
        if e["hash"] != rec["head"]:
            return {"ok": False, "problem": f"history rewritten: seq {rec['seq']} no longer matches its anchored hash"}
    return {"ok": True, "checkpoints": n, "last_anchored_seq": last["seq"] if last else None,
            "unanchored_tail": (max(by_seq) - last["seq"]) if last and by_seq else None}


def prune(guard, before_seq: int, archive: Path | str) -> dict:
    """Move entries with seq < before_seq to an archive file and resume the chain from a signed retention point."""
    with guard.store.lock():
        entries = guard.audit.snapshot()
        v = guard.audit.verify(entries)
        if not v["ok"]:
            return {"ok": False, "reason": "refusing to prune a chain that does not verify"}
        old = [e for e in entries if e["seq"] < before_seq]
        keep = [e for e in entries if e["seq"] >= before_seq]
        if not old or not keep:
            return {"ok": False, "reason": "nothing to prune at that boundary"}
        archive = Path(archive).expanduser()
        archive.parent.mkdir(parents=True, exist_ok=True)
        with archive.open("a", encoding="utf-8") as fh:
            for e in old:
                fh.write(json.dumps(e, ensure_ascii=False) + "\n")
        home = guard.audit.path.parent
        body = {"first_seq": keep[0]["seq"], "prev_hash": keep[0]["prev_hash"]}
        mac = hmac.new(guard.store.key, canonical_json(body).encode(), hashlib.sha256).hexdigest()
        tmp = home / "retention.json.tmp"
        tmp.write_text(json.dumps({**body, "mac": mac, "pruned": len(old), "archive": str(archive)}), encoding="utf-8")
        log_tmp = guard.audit.path.with_suffix(".jsonl.tmp")
        log_tmp.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in keep), encoding="utf-8")
        os.replace(tmp, home / "retention.json")
        os.replace(log_tmp, guard.audit.path)
        guard.audit.entries, guard.audit._offset = [], 0
        guard.audit.append("audit_pruned", "provenant", {"pruned": len(old), "first_seq": keep[0]["seq"]})
        return {"ok": True, "pruned": len(old), "first_seq": keep[0]["seq"], "archive": str(archive)}


def export(guard, out: Path | str) -> dict:
    """A self-contained copy for review: entries, retention record and the verification result."""
    out = Path(out).expanduser()
    entries = guard.audit.snapshot()
    rp = guard.audit.path.parent / "retention.json"
    doc = {"exported_at": time.time(), "verify": guard.audit.verify(entries),
           "retention": json.loads(rp.read_text(encoding="utf-8")) if rp.exists() else None, "entries": entries}
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"ok": True, "entries": len(entries), "out": str(out)}
