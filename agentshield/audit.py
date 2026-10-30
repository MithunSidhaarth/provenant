"""Tamper-evident audit trail.

Each entry is an append-only JSON line containing:
    seq, ts, event, session_id, data, prev_hash, hash, mac
where hash = SHA-256(canonical JSON of every other field) and prev_hash links to the previous
entry. Editing, deleting, reordering or inserting any entry breaks the chain at that point.

The optional HMAC (mac) is keyed with AGENTSHIELD_AUDIT_KEY from the environment, or a random
per-process key when unset. A plain hash chain detects accidental or naive tampering; the MAC
additionally stops an attacker who can rewrite the file from silently recomputing the chain.
Keys are never written to the log or to source control.

Inputs are logged, but values matching known secrets are replaced with a fingerprint so the
audit trail does not become a second copy of the sensitive data it protects.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import canonical_json, sha256_hex

GENESIS = "0" * 64


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class AuditLog:
    def __init__(self, path: Path | str | None = None, key: bytes | None = None,
                 redact: dict[str, str] | None = None) -> None:
        self.path = Path(path) if path else None
        env_key = os.environ.get("AGENTSHIELD_AUDIT_KEY")
        self._key = key or (env_key.encode() if env_key else secrets.token_bytes(32))
        self._redact = redact or {}
        self._lock = threading.Lock()
        self.entries: list[dict] = []
        if self.path and self.path.exists():
            self.entries = [json.loads(l) for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]

    # ------------------------------------------------------------------------------
    def _scrub(self, obj: Any) -> Any:
        if isinstance(obj, str):
            for name, value in self._redact.items():
                if value and value in obj:
                    obj = obj.replace(value, f"[REDACTED:{name}:{sha256_hex(value)[:8]}]")
            return obj
        if isinstance(obj, dict):
            return {k: self._scrub(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._scrub(v) for v in obj]
        return obj

    def _mac(self, h: str) -> str:
        return hmac.new(self._key, h.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def _entry_hash(entry: dict) -> str:
        body = {k: v for k, v in entry.items() if k not in ("hash", "mac")}
        return sha256_hex(canonical_json(body))

    def append(self, event: str, session_id: str, data: dict) -> dict:
        with self._lock:
            prev = self.entries[-1]["hash"] if self.entries else GENESIS
            entry = {"seq": len(self.entries), "ts": utc_now(), "event": event,
                     "session_id": session_id, "data": self._scrub(data), "prev_hash": prev}
            entry["hash"] = self._entry_hash(entry)
            entry["mac"] = self._mac(entry["hash"])
            self.entries.append(entry)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            return entry

    def verify(self, entries: list[dict] | None = None) -> dict:
        """Recompute the chain. Returns {ok, checked, first_bad_seq, problem}."""
        entries = self.entries if entries is None else entries
        prev = GENESIS
        for i, e in enumerate(entries):
            problem = None
            if e.get("seq") != i:
                problem = f"sequence gap or reorder at position {i}"
            elif e.get("prev_hash") != prev:
                problem = "prev_hash does not link to the previous entry (deleted, inserted or reordered)"
            elif self._entry_hash(e) != e.get("hash"):
                problem = "entry content does not match its hash (modified)"
            elif not hmac.compare_digest(self._mac(e["hash"]), str(e.get("mac", ""))):
                problem = "MAC invalid (chain recomputed without the audit key)"
            if problem:
                return {"ok": False, "checked": i, "first_bad_seq": i, "problem": problem}
            prev = e["hash"]
        return {"ok": True, "checked": len(entries), "first_bad_seq": None, "problem": None,
                "head": prev}

    def for_session(self, session_id: str) -> list[dict]:
        return [e for e in self.entries if e["session_id"] == session_id]
