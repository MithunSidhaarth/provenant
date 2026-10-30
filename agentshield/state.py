"""SQLite authorization state for the live guard: sessions, approvals, execution grants and audit checkpoints.

Why SQLite: hooks and proxies are separate short-lived processes, and the security-critical transitions
(pending -> approved -> used, grant issued -> redeemed) must be atomic across them. Every transition is a
single `BEGIN IMMEDIATE` transaction whose UPDATE carries the full precondition in its WHERE clause, so two
processes racing to consume one approval cannot both see rowcount 1.

Fail closed: if the database cannot be opened, fails its integrity check, or has a schema newer than this
code understands, `StateDB` raises `StateUnavailable` and callers treat that as DENY.

Backup: `StateDB.backup(path)` uses SQLite's online backup API, so it is consistent while other processes
write. Migrations are numbered and recorded in `PRAGMA user_version`; they only ever add.
"""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SCHEMA_VERSION = 2

MIGRATIONS: dict[int, list[str]] = {
    1: [
        """CREATE TABLE sessions (
               session_id TEXT PRIMARY KEY,
               mode       TEXT NOT NULL,
               data       TEXT NOT NULL,
               updated_at REAL NOT NULL)""",
        """CREATE TABLE approvals (
               approval_id TEXT PRIMARY KEY,
               fingerprint TEXT NOT NULL,
               status      TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','used','expired')),
               mode        TEXT NOT NULL,
               tool        TEXT NOT NULL,
               args        TEXT NOT NULL,
               session_id  TEXT NOT NULL,
               source      TEXT NOT NULL,
               reasons     TEXT NOT NULL,
               created_at  REAL NOT NULL,
               expires_at  REAL NOT NULL,
               decided_by  TEXT,
               decided_at  REAL,
               channel     TEXT,
               evidence    TEXT,
               used_at     REAL,
               used_by_call TEXT)""",
        "CREATE INDEX approvals_fp ON approvals (fingerprint, status)",
        """CREATE TABLE grants (
               grant_id    TEXT PRIMARY KEY,
               fingerprint TEXT NOT NULL,
               mode        TEXT NOT NULL,
               session_id  TEXT NOT NULL,
               issued_at   REAL NOT NULL,
               expires_at  REAL NOT NULL,
               redeemed_at REAL)""",
    ],
    2: [
        """CREATE TABLE checkpoints (
               id         INTEGER PRIMARY KEY AUTOINCREMENT,
               seq        INTEGER NOT NULL,
               head       TEXT NOT NULL,
               created_at REAL NOT NULL,
               anchored_to TEXT)""",
    ],
}


class StateUnavailable(RuntimeError):
    """Authorization state cannot be read or trusted. Protected actions must be blocked."""


class StateDB:
    def __init__(self, path: Path | str, timeout: float = 10.0) -> None:
        self.path = Path(path)
        self.timeout = timeout
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._conn() as c:
                ok = c.execute("PRAGMA quick_check").fetchone()[0]
                if ok != "ok":
                    raise StateUnavailable(f"state database failed its integrity check: {ok}")
                self._migrate(c)
        except StateUnavailable:
            raise
        except sqlite3.Error as exc:
            raise StateUnavailable(f"state database unavailable: {type(exc).__name__}: {exc}") from exc

    # --- plumbing ------------------------------------------------------------------------------
    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        c = sqlite3.connect(self.path, timeout=self.timeout, isolation_level=None)
        try:
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=FULL")
            c.execute(f"PRAGMA busy_timeout={int(self.timeout * 1000)}")
            yield c
        finally:
            c.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """One write transaction. BEGIN IMMEDIATE takes the write lock up front, so check-then-update is atomic."""
        try:
            with self._conn() as c:
                c.execute("BEGIN IMMEDIATE")
                try:
                    yield c
                    c.execute("COMMIT")
                except BaseException:
                    c.execute("ROLLBACK")
                    raise
        except sqlite3.Error as exc:
            raise StateUnavailable(f"state transaction failed: {type(exc).__name__}: {exc}") from exc

    def _migrate(self, c: sqlite3.Connection) -> None:
        current = c.execute("PRAGMA user_version").fetchone()[0]
        if current > SCHEMA_VERSION:
            raise StateUnavailable(f"state schema v{current} is newer than this Provenant (v{SCHEMA_VERSION})")
        for v in range(current + 1, SCHEMA_VERSION + 1):
            c.execute("BEGIN IMMEDIATE")
            try:
                if c.execute("PRAGMA user_version").fetchone()[0] >= v:   # another process migrated first
                    c.execute("ROLLBACK")
                    continue
                for stmt in MIGRATIONS[v]:
                    c.execute(stmt)
                c.execute(f"PRAGMA user_version={v}")
                c.execute("COMMIT")
            except BaseException:
                c.execute("ROLLBACK")
                raise

    def schema_version(self) -> int:
        with self._conn() as c:
            return c.execute("PRAGMA user_version").fetchone()[0]

    def backup(self, dest: Path | str) -> None:
        with self._conn() as c:
            out = sqlite3.connect(dest)
            try:
                c.backup(out)
            finally:
                out.close()

    # --- sessions ------------------------------------------------------------------------------
    def load_session(self, sid: str, default: dict) -> dict:
        with self._conn() as c:
            row = c.execute("SELECT data FROM sessions WHERE session_id=?", (sid,)).fetchone()
        if row is None:
            return default
        data = json.loads(row["data"])
        if not isinstance(data, dict):
            raise StateUnavailable("session record is corrupt")
        return data

    def save_session(self, sid: str, mode: str, data: dict) -> None:
        with self.tx() as c:
            c.execute("INSERT INTO sessions VALUES (?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET "
                      "data=excluded.data, updated_at=excluded.updated_at", (sid, mode, json.dumps(data), time.time()))

    # --- approvals -----------------------------------------------------------------------------
    def find_pending(self, fingerprint: str, mode: str, now: float) -> str | None:
        with self._conn() as c:
            row = c.execute("SELECT approval_id FROM approvals WHERE fingerprint=? AND mode=? AND status='pending' "
                            "AND expires_at>?", (fingerprint, mode, now)).fetchone()
        return row["approval_id"] if row else None

    def create_approval(self, rec: dict) -> None:
        with self.tx() as c:
            c.execute("INSERT INTO approvals (approval_id, fingerprint, status, mode, tool, args, session_id, source, "
                      "reasons, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                      (rec["approval_id"], rec["fingerprint"], "pending", rec["mode"], rec["tool"],
                       json.dumps(rec["args"]), rec["session_id"], rec["source"], json.dumps(rec["reasons"]),
                       rec["created_at"], rec["expires_at"]))

    def get_approval(self, approval_id: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM approvals WHERE approval_id=?", (approval_id,)).fetchone()
        return _approval(row) if row else None

    def list_approvals(self, status: str | None = None) -> list[dict]:
        with self._conn() as c:
            rows = (c.execute("SELECT * FROM approvals WHERE status=? ORDER BY created_at", (status,)) if status
                    else c.execute("SELECT * FROM approvals ORDER BY created_at")).fetchall()
        return [_approval(r) for r in rows]

    def decide(self, approval_id: str, approve: bool, approver: str, now: float, channel: str = "cli",
               evidence: dict | None = None) -> dict:
        """pending -> approved/rejected, atomically, only while unexpired."""
        with self.tx() as c:
            row = c.execute("SELECT status, expires_at FROM approvals WHERE approval_id=?", (approval_id,)).fetchone()
            if row is None:
                return {"ok": False, "reason": "no such approval request"}
            if row["status"] != "pending":
                return {"ok": False, "reason": f"request is already {row['status']}"}
            if now >= row["expires_at"]:
                c.execute("UPDATE approvals SET status='expired' WHERE approval_id=?", (approval_id,))
                return {"ok": False, "reason": "request expired"}
            cur = c.execute("UPDATE approvals SET status=?, decided_by=?, decided_at=?, channel=?, evidence=? "
                            "WHERE approval_id=? AND status='pending' AND expires_at>?",
                            ("approved" if approve else "rejected", approver, now, channel,
                             json.dumps(evidence or {}), approval_id, now))
            if cur.rowcount != 1:
                return {"ok": False, "reason": "request changed state concurrently"}
        return {"ok": True, "status": "approved" if approve else "rejected"}

    def consume_approval(self, fingerprint: str, mode: str, now: float, call_id: str) -> dict | None:
        """approved -> used for exactly one caller. Mode must match: demo approvals never unlock live calls."""
        with self.tx() as c:
            row = c.execute("SELECT * FROM approvals WHERE fingerprint=? AND mode=? AND status='approved' AND expires_at>? "
                            "ORDER BY decided_at LIMIT 1", (fingerprint, mode, now)).fetchone()
            if row is None:
                return None
            cur = c.execute("UPDATE approvals SET status='used', used_at=?, used_by_call=? "
                            "WHERE approval_id=? AND status='approved'", (now, call_id, row["approval_id"]))
            if cur.rowcount != 1:
                return None
        return _approval(row)

    def expire(self, now: float) -> int:
        with self.tx() as c:
            return c.execute("UPDATE approvals SET status='expired' WHERE status IN ('pending','approved') "
                             "AND expires_at<=?", (now,)).rowcount

    # --- grants --------------------------------------------------------------------------------
    def issue_grant(self, grant_id: str, fingerprint: str, mode: str, sid: str, now: float, ttl: float) -> None:
        with self.tx() as c:
            c.execute("INSERT INTO grants VALUES (?,?,?,?,?,?,NULL)", (grant_id, fingerprint, mode, sid, now, now + ttl))

    def redeem_grant(self, grant_id: str, fingerprint: str, mode: str, now: float) -> bool:
        """A grant runs exactly one call: the one whose fingerprint it was issued for, in the same mode."""
        with self.tx() as c:
            cur = c.execute("UPDATE grants SET redeemed_at=? WHERE grant_id=? AND fingerprint=? AND mode=? "
                            "AND redeemed_at IS NULL AND expires_at>?", (now, grant_id, fingerprint, mode, now))
            return cur.rowcount == 1

    # --- audit checkpoints ---------------------------------------------------------------------
    def add_checkpoint(self, seq: int, head: str, anchored_to: str | None) -> None:
        with self.tx() as c:
            c.execute("INSERT INTO checkpoints (seq, head, created_at, anchored_to) VALUES (?,?,?,?)",
                      (seq, head, time.time(), anchored_to))

    def checkpoints(self) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM checkpoints ORDER BY id").fetchall()]


def _approval(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["args"] = json.loads(d["args"])
    d["reasons"] = json.loads(d["reasons"])
    d["evidence"] = json.loads(d["evidence"]) if d.get("evidence") else None
    return d
