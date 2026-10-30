"""Phone approval: a held call is explained to a human over the phone by the existing claude-call-me skill
(Ivy, a Bolna voice agent), and Provenant decides, from the returned transcript, whether a human said yes.

    Guard holds call  ->  build_task(approval)  ->  claude-call-me call.ps1 phones the user
                      <-  {status, voicemail, transcript}  <-  Ivy talks, user answers
    validate(result, approval)  ->  only an explicit spoken "approve <code>" for THIS request counts
    Guard.decide(..., channel="phone")  ->  SQLite: pending -> approved (single use, unexpired, same mode)

The voice agent never authorizes anything. It only carries words. Provenant reads the user's own turns of
the transcript with deterministic rules:

* the call must have completed, been answered by a person (not voicemail) and have a transcript;
* the user must say an approval word AND the 4-digit confirmation code derived from this request's
  fingerprint and id, so a "yes" to some other question, or to an earlier call, does not match;
* any refusal word anywhere in the user's turns, or both approve and deny, means no;
* questions are not approvals: a user turn that is a question never counts as the approving turn;
* timeouts, errors, missing transcripts and anything unparseable mean no.

The adapter does not reimplement Bolna. It runs the user's installed claude-call-me `call.ps1`
(found via PROVENANT_CALLME_SCRIPT, or ~/.claude/skills/call-me/call.ps1). Credentials stay in that skill's
user environment variables; Provenant never reads or logs them, and only a transcript digest is audited.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable

from .models import sha256_hex

APPROVE_WORDS = ("approve", "approved", "i approve", "authorize", "authorise", "go ahead", "confirm", "confirmed", "yes")
DENY_WORDS = ("deny", "denied", "reject", "rejected", "no", "don't", "do not", "stop", "cancel", "block", "refuse",
              "not approved", "never")
_NUM = {"zero": "0", "oh": "0", "o": "0", "one": "1", "two": "2", "to": "2", "too": "2", "three": "3", "four": "4",
        "for": "4", "five": "5", "six": "6", "seven": "7", "eight": "8", "ate": "8", "nine": "9", "niner": "9"}
_USER_PREFIX = re.compile(r"^\s*(user|human|caller|customer)\s*:\s*", re.IGNORECASE)
_AGENT_PREFIX = re.compile(r"^\s*(assistant|agent|ivy|bot|ai)\s*:\s*", re.IGNORECASE)


def confirmation_code(approval: dict, key: bytes) -> str:
    """4 digits bound to this approval id and the exact call fingerprint (HMAC, so not guessable from the id)."""
    mac = hmac.new(key, f"{approval['approval_id']}|{approval['fingerprint']}".encode(), hashlib.sha256).hexdigest()
    return f"{int(mac[:8], 16) % 10000:04d}"


def summarize_action(approval: dict) -> str:
    """Plain words a person can judge on the phone. Values are truncated; secrets were refused earlier."""
    args = approval.get("args") or {}
    tool = str(approval.get("tool", "a tool")).split("__")[-1]
    bits = []
    for k, v in list(args.items())[:4] if isinstance(args, dict) else []:
        s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
        bits.append(f"{k}: {s[:120]}")
    reasons = "; ".join(approval.get("reasons") or [])[:300]
    return f"The agent wants to run {tool}" + (f" with {', '.join(bits)}" if bits else "") + f". Provenant held it because: {reasons}."


def build_task(approval: dict, code: str) -> str:
    """The instructions Ivy gets for this one call."""
    spoken = " ".join(code)
    return (
        "You are calling about ONE action that Provenant, the user's AI-agent firewall, has paused.\n"
        f"Action: {summarize_action(approval)}\n"
        f"Request id: {approval['approval_id']}. Confirmation code: {spoken}.\n"
        "Explain the action in one or two sentences, then answer any questions about it plainly, using only the "
        "details above. Do not guess or add details.\n"
        f"Then ask: 'To approve, say approve and the code {spoken}. To refuse, say deny.'\n"
        "You cannot approve anything yourself and you must not say that the action has been approved or run. "
        "Repeat back what the user said and end the call. If the user is unsure, tell them the action will stay blocked."
    )


def user_turns(transcript: Any) -> list[str]:
    """Only the human side of the conversation. Bolna returns 'assistant: ...\\nuser: ...' text."""
    if isinstance(transcript, list):
        out = []
        for t in transcript:
            if isinstance(t, dict) and str(t.get("role", "")).lower() in ("user", "human", "caller"):
                out.append(str(t.get("content") or t.get("text") or ""))
        return out
    if not isinstance(transcript, str):
        return []
    turns, current = [], None
    for line in transcript.splitlines():
        if _USER_PREFIX.match(line):
            current = _USER_PREFIX.sub("", line)
            turns.append(current)
        elif _AGENT_PREFIX.match(line):
            current = None
        elif current is not None and line.strip():
            turns[-1] += " " + line.strip()
    return turns


def _digits(text: str) -> str:
    words = re.findall(r"[a-z]+|\d", text.lower())
    return "".join(w if w.isdigit() else _NUM.get(w, " ") for w in words)


def _has(words: tuple[str, ...], text: str) -> bool:
    t = " " + re.sub(r"[^a-z' ]+", " ", text.lower()) + " "
    return any(f" {w} " in t for w in words)


def validate(result: dict, approval: dict, code: str) -> dict:
    """Deterministic: {approved: bool, reason: str}. Anything short of an unambiguous, coded yes is a no."""
    if not isinstance(result, dict):
        return {"approved": False, "reason": "no call result"}
    if result.get("status") != "completed":
        return {"approved": False, "reason": f"call did not complete (status {result.get('status')!r})"}
    if result.get("voicemail"):
        return {"approved": False, "reason": "answered by voicemail"}
    turns = user_turns(result.get("transcript"))
    if not turns:
        return {"approved": False, "reason": "no words from the user in the transcript"}
    if any(_has(DENY_WORDS, t) for t in turns):
        return {"approved": False, "reason": "the user refused, or said no at some point (treated as a refusal)"}
    for t in turns:
        if t.strip().endswith("?") or re.match(r"^\s*(what|why|how|who|which|can|could|will|would|is|does)\b", t.lower()):
            continue                             # a question is never an approval
        if _has(APPROVE_WORDS, t) and code in _digits(t):
            return {"approved": True, "reason": "the user said approve with the matching confirmation code"}
    if any(_has(APPROVE_WORDS, t) for t in turns):
        return {"approved": False, "reason": "approval words without the matching confirmation code"}
    return {"approved": False, "reason": "no explicit approval"}


def find_callme_script() -> Path | None:
    env = os.environ.get("PROVENANT_CALLME_SCRIPT")
    for p in ([Path(env)] if env else []) + [Path.home() / ".claude" / "skills" / "call-me" / "call.ps1"]:
        if p.is_file():
            return p
    return None


def run_callme(task: str, timeout_sec: int = 300, script: Path | None = None) -> dict:
    """Run the user's claude-call-me call.ps1 and parse its final JSON object. Errors become a failed result."""
    script = script or find_callme_script()
    if script is None:
        return {"status": "not_configured", "error": "claude-call-me is not installed (set PROVENANT_CALLME_SCRIPT)"}
    shell = shutil.which("powershell") or shutil.which("pwsh")
    if not shell:
        return {"status": "not_configured", "error": "PowerShell is not available"}
    try:
        p = subprocess.run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-Task", task,
                            "-TimeoutSec", str(timeout_sec)], capture_output=True, text=True, timeout=timeout_sec + 60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "error": type(exc).__name__}
    return parse_callme_output(p.stdout) if p.returncode == 0 else {"status": "error", "error": f"exit {p.returncode}"}


def parse_callme_output(stdout: str) -> dict:
    """call.ps1 prints progress lines, then one JSON object. Take the last object that parses."""
    start = stdout.rfind("\n{")
    start = 0 if stdout.lstrip().startswith("{") and start < 0 else start + 1
    try:
        obj = json.loads(stdout[start:])
        return obj if isinstance(obj, dict) else {"status": "error", "error": "unexpected output"}
    except ValueError:
        return {"status": "error", "error": "unparseable output"}


def phone_approve(guard, approval_id: str, runner: Callable[[str], dict] | None = None,
                  phone_label: str = "phone") -> dict:
    """The whole flow for one held call. Only Guard.decide changes state, and only on a validated yes."""
    approval = guard.get_approval(approval_id)
    if approval is None or approval["status"] != "pending" or approval["mode"] != guard.mode:
        return {"ok": False, "approved": False, "reason": "no pending request with that id in this mode"}
    code = confirmation_code(approval, guard.store.key)
    task = build_task(approval, code)
    guard.audit.append("phone_call_started", approval["session_id"], {"approval_id": approval_id})
    try:
        result = (runner or run_callme)(task)
    except Exception as exc:                       # a broken provider leaves the action blocked
        result = {"status": "error", "error": type(exc).__name__}
    verdict = validate(result, approval, code)
    evidence = {"call_status": str(result.get("status"))[:40], "voicemail": bool(result.get("voicemail")),
                "execution_id": str(result.get("execution_id", ""))[:80],
                "transcript_sha256": sha256_hex(json.dumps(result.get("transcript"), ensure_ascii=False, default=str)),
                "validator": verdict["reason"]}
    guard.audit.append("phone_call_result", approval["session_id"], {"approval_id": approval_id, **evidence})
    if verdict["approved"]:
        r = guard.decide(approval_id, f"human:{phone_label}", True, channel="phone", evidence=evidence)
        return {"ok": r["ok"], "approved": r["ok"], "reason": verdict["reason"] if r["ok"] else r["reason"]}
    if "refused" in verdict["reason"]:
        guard.decide(approval_id, f"human:{phone_label}", False, channel="phone", evidence=evidence)
    return {"ok": True, "approved": False, "reason": verdict["reason"]}
