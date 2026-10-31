"""Live inbox watch that the local dashboard starts and stops.

When the ops console opens it asks the local server to start this watcher. The watcher polls the mailbox over
IMAP (read-only, BODY.PEEK so nothing is marked read), runs every NEW message through the mail scanner
(mailscan.score_mail), records the verdict in the audit log (sender, subject, score and reason codes only, never the
body), and phones the user through the built-in Bolna caller when a mail reaches the alert level.

Mailbox credentials are the ones saved by `provenant mail watch --setup` (~/.provenant/mail.json, DPAPI on Windows)
or PROVENANT_IMAP_USER / PROVENANT_IMAP_PASSWORD. The dashboard never asks for or receives a password.
Phone: bolna.py (`provenant phone setup`) first, else the `provenant mail setup` caller in mail_security.py.

Observational only: nothing here decides whether an agent's tool call runs, and nothing deletes or moves mail.
"""
from __future__ import annotations

import collections
import threading
import time
from typing import Any, Callable

from . import mail_security as ms
from . import mailscan

_RANK = {lvl: i for i, lvl in enumerate(mailscan.LEVELS)}
SESSION = "mail-watch"


def _attachment_names(raw: bytes) -> list[str]:
    import email
    from email import policy
    try:
        msg = email.message_from_bytes(raw, policy=policy.default)
    except Exception:
        return []
    names = []
    for part in msg.walk():
        name = part.get_filename()
        if name:
            names.append(str(name)[:120])
    return names[:20]


def scan_raw(raw: bytes) -> dict:
    """RFC 822 bytes -> mailscan verdict. The body is used for scoring and then dropped."""
    m = ms.parse_raw_email(raw)
    auth = m.get("headers", "")
    verdict = mailscan.score_mail({"id": m.get("id", ""), "from": m.get("sender", ""), "subject": m.get("subject", ""),
                                   "reply_to": m.get("reply_to", ""), "auth": auth, "body": m.get("body", ""),
                                   "attachments": _attachment_names(raw)})
    verdict["fingerprint"] = ms.mail_fingerprint(m)
    return verdict


def alert_task(v: dict) -> str:
    why = "; ".join(s["reason"] for s in v["signals"][:3])
    return ("Phone call purpose: warn the user about one suspicious email that just arrived in their inbox. "
            "This is a heads-up, not an approval request.\n"
            f"Sender: {v['from'][:80]}. Subject: {v['subject'][:80]}. Provenant risk: {v['level']} ({v['score']} of 100). "
            f"Why: {why[:300]}.\n"
            "Say this in two or three short sentences, plainly. Tell them not to click links, open attachments, reply "
            "or share any code or password until they have checked the sender another way. Provenant has not changed "
            "or deleted the mail. Do not read out long addresses or links. Ask if they want anything else, then end the call.")


def default_caller(task: str) -> dict:
    """Built-in Bolna caller first (provenant phone setup), else the mail-setup caller. Never raises."""
    from . import bolna
    try:
        if bolna.configured():
            r = bolna.run_call(task, timeout_sec=240)
            return {"ok": r.get("status") not in ("error", "not_configured"), "status": r.get("status"),
                    "execution_id": r.get("execution_id"), "error": r.get("error")}
        if ms._user_env("BOLNA_API_KEY") and ms._user_env("CALL_ME_PHONE"):
            r = ms.send_phone_alert(task)
            return {"ok": bool(r.get("ok")), "status": r.get("status", "error"), "execution_id": r.get("execution_id"),
                    "error": r.get("error")}
        return {"ok": False, "status": "not_configured", "error": "phone not set up: run provenant phone setup"}
    except Exception as exc:
        return {"ok": False, "status": "error", "error": f"{type(exc).__name__}: {str(exc)[:160]}"}


def phone_ready() -> bool:
    from . import bolna
    try:
        return bolna.configured() or bool(ms._user_env("BOLNA_API_KEY") and ms._user_env("CALL_ME_PHONE"))
    except Exception:
        return False


def alert_level() -> str:
    from . import bolna
    try:
        lvl = str((bolna.load().get("alerts") or {}).get("min_level", "high"))
    except Exception:
        lvl = "high"
    return lvl if lvl in _RANK else "high"


def inbox_credentials() -> tuple[str, str, str] | None:
    """Saved or env credentials only: the dashboard path is never interactive."""
    import os
    data = ms._load_settings()
    host = data.get("imap_host") or "imap.gmail.com"
    user = os.environ.get("PROVENANT_IMAP_USER", "") or data.get("imap_user", "")
    password = os.environ.get("PROVENANT_IMAP_PASSWORD", "") or data.get("imap_password", "")
    return (host, user, password) if user and password else None


def _masked(user: str) -> str:
    return user[:2] + "***@" + user.split("@")[-1] if "@" in user else "***"


class MailWatcher:
    def __init__(self, audit: Callable[[str, str, dict], Any] | None = None, connect: Callable | None = None,
                 credentials: Callable[[], tuple[str, str, str] | None] = inbox_credentials,
                 caller: Callable[[str], dict] = default_caller, ready: Callable[[], bool] = phone_ready,
                 level: Callable[[], str] = alert_level, interval: float = 15.0, max_calls_per_hour: int = 5,
                 sleep: Callable[[float], None] | None = None) -> None:
        self._audit = audit
        self._connect = connect or (lambda h, u, p: ms._imap_connect(h, u, p, "INBOX"))
        self._credentials, self._caller, self._ready, self._level = credentials, caller, ready, level
        self.interval, self.max_calls_per_hour = interval, max_calls_per_hour
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sleep = sleep
        self.mails: collections.deque = collections.deque(maxlen=100)
        self._calls: list[float] = []
        self._seen: set[str] = set()
        self.state = {"running": False, "state": "stopped", "account": None, "last_check": None, "checked": 0,
                      "scanned": 0, "flagged": 0, "calls": 0, "error": None, "started_at": None}

    # -- control -----------------------------------------------------------------------------------------
    def start(self) -> dict:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return self.status()
            creds = self._credentials()
            if not creds:
                self.state.update(state="not_configured", running=False,
                                  error="No mailbox connected. Run 'provenant mail watch --setup' once in a terminal "
                                        "(Gmail: use an App Password).")
                return self.status()
            self._stop.clear()
            self.state.update(running=True, state="connecting", account=_masked(creds[1]), error=None,
                              started_at=time.strftime("%Y-%m-%dT%H:%M:%S"))
            self._thread = threading.Thread(target=self._run, args=(creds,), name="provenant-mail-watch", daemon=True)
            self._thread.start()
        self._log("mail_watch_started", {"account": self.state["account"]})
        return self.status()

    def stop(self) -> dict:
        self._stop.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout=5)
        with self._lock:
            if self.state["running"]:
                self._log("mail_watch_stopped", {"account": self.state["account"]})
            self.state.update(running=False, state="stopped")
        return self.status()

    def status(self) -> dict:
        lvl = self._level()
        return {**self.state, "alert_level": lvl, "phone_ready": self._ready(), "interval": self.interval,
                "mails": list(self.mails)[::-1]}

    # -- loop --------------------------------------------------------------------------------------------
    def _wait(self, seconds: float) -> bool:
        if self._sleep:
            self._sleep(seconds)
            return self._stop.is_set()
        return self._stop.wait(seconds)

    def _run(self, creds: tuple[str, str, str]) -> None:
        host, user, password = creds
        conn, last = None, None
        try:
            while not self._stop.is_set():
                try:
                    if conn is None:
                        conn = self._connect(host, user, password)
                        if last is None:          # only mail that arrives after the dashboard opened
                            existing = ms._uids(conn, "ALL")
                            last = existing[-1] if existing else 0
                    if hasattr(conn, "select"):   # Gmail only shows new mail after a re-select
                        conn.select('"INBOX"', readonly=True)
                    new = [u for u in ms._uids(conn, f"UID {last + 1}:*") if u > last]
                    for uid in new:
                        last = max(last, uid)
                        raw = ms._fetch(conn, uid)
                        if raw:
                            self._handle(raw)
                    self.state.update(state="watching", last_check=time.strftime("%Y-%m-%dT%H:%M:%S"),
                                      checked=self.state["checked"] + 1, error=None)
                except Exception as exc:
                    self.state.update(state="reconnecting", error=f"{type(exc).__name__}: {str(exc)[:160]}")
                    try:
                        if conn is not None:
                            conn.logout()
                    except Exception:
                        pass
                    conn = None
                if self._wait(self.interval):
                    break
        finally:
            try:
                if conn is not None:
                    conn.logout()
            except Exception:
                pass
            self.state.update(running=False, state="stopped" if self._stop.is_set() else "error")

    def _handle(self, raw: bytes) -> None:
        v = scan_raw(raw)
        if v["fingerprint"] in self._seen:
            return
        self._seen.add(v["fingerprint"])
        self.state["scanned"] += 1
        flagged = v["level"] != "low"
        if flagged:
            self.state["flagged"] += 1
        row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "from": v["from"], "subject": v["subject"], "score": v["score"],
               "level": v["level"], "signals": v["signals"], "fingerprint": v["fingerprint"], "call": None}
        self._log("mail_verdict", {"source": "imap-watch", "id": v["id"], "from": v["from"], "subject": v["subject"],
                                   "score": v["score"], "level": v["level"], "signals": v["signals"],
                                   "fingerprint": v["fingerprint"]})
        if _RANK[v["level"]] >= _RANK[self._level()]:
            row["call"] = self._maybe_call(v)
        self.mails.append(row)

    def _maybe_call(self, v: dict) -> dict:
        if not self._ready():
            return {"status": "not_configured", "detail": "phone not set up (provenant phone setup)"}
        now = time.time()
        self._calls = [t for t in self._calls if now - t < 3600]
        if len(self._calls) >= self.max_calls_per_hour:
            return {"status": "skipped", "detail": f"call limit reached ({self.max_calls_per_hour} per hour)"}
        self._calls.append(now)
        self.state["calls"] += 1
        call = {"status": "calling", "detail": "placing call"}

        def run() -> None:
            r = self._caller(alert_task(v))
            call.update(status=r.get("status") or ("started" if r.get("ok") else "error"),
                        detail=(r.get("error") or "")[:160] or None, execution_id=r.get("execution_id"))
            self._log("mail_phone_alert", {"fingerprint": v["fingerprint"], "status": call["status"],
                                           "execution_id": r.get("execution_id")})
        threading.Thread(target=run, name="provenant-mail-call", daemon=True).start()
        return call

    def _log(self, event: str, data: dict) -> None:
        if self._audit:
            try:
                self._audit(event, SESSION, data)
            except Exception:
                pass


_WATCHER: MailWatcher | None = None
_WLOCK = threading.Lock()


def shared() -> MailWatcher:
    """One watcher per dashboard server process, writing to the Guard audit chain."""
    global _WATCHER
    with _WLOCK:
        if _WATCHER is None:
            from . import guard as guard_mod
            store = guard_mod.Store()
            _WATCHER = MailWatcher(audit=lambda ev, sid, data: store.audit.append(ev, sid, data))
        return _WATCHER
