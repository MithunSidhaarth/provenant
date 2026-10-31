"""Built-in phone calls through Bolna (the voice platform behind the claude-call-me skill).

Provenant uses this for two things: phoning the user about a held call (voice.py) and alerting them about a
suspicious mail (mailscan.py). It needs one credential, the user's Bolna API key, and their own phone number.

Behaviour is ported from the claude-call-me skill's call.ps1 (create a reusable agent once, POST /call, poll
/executions/{id}), using only the standard library. Attribution: https://github.com/MithunSidhaarth/claude-call-me

Storage: ~/.provenant/phone.json (mode 0600 where the OS supports it). The BOLNA_API_KEY and CALL_ME_PHONE
environment variables win over the file. The key is never printed, logged or put in the audit log.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

API = "https://api.bolna.ai"
FINAL = ("completed", "balance-low", "busy", "no-answer", "canceled", "failed", "stopped", "error")
PERSONA = ("You are Ivy, the voice of Provenant, the security firewall that sits between the user's AI agents and their "
           "tools and watches their inbox. You phone the user when Provenant catches something: a suspicious email, or an "
           "agent action held for their approval.\n"
           "Personality: crisp, calm and quietly warm, a composed security professional who respects their time. Plain "
           "words, no jargon, no filler. Never say you work for Claude or a coding agent. If asked who you are: "
           "\"I'm Ivy from Provenant, your AI agent security guard.\"")
# Bump when the agent's name or greeting changes: a saved agent with another version is replaced on the next call.
AGENT_VERSION = "provenant-2"
E164 = re.compile(r"^\+[1-9]\d{7,14}$")

Opener = Callable[[urllib.request.Request, float], Any]


def home_dir() -> Path:
    return Path(os.environ.get("PROVENANT_HOME") or (Path.home() / ".provenant"))


def config_path(home: Path | None = None) -> Path:
    return (home or home_dir()) / "phone.json"


def load(home: Path | None = None) -> dict:
    cfg: dict = {}
    try:
        cfg = json.loads(config_path(home).read_text(encoding="utf-8"))
        if not isinstance(cfg, dict):
            cfg = {}
    except (OSError, ValueError):
        cfg = {}
    cfg = dict(cfg)
    if os.environ.get("BOLNA_API_KEY"):
        cfg["api_key"] = os.environ["BOLNA_API_KEY"]
    if os.environ.get("CALL_ME_PHONE"):
        cfg["phone"] = os.environ["CALL_ME_PHONE"]
    # BOLNA_AGENT_ID belongs to the claude-call-me skill ("calling for your Claude agent"): never reuse it here.
    if home is None and not (cfg.get("api_key") and cfg.get("phone")):
        try:                                           # also accept what `provenant mail setup` saved (mail.json, DPAPI)
            from .mail_security import _load_settings
            mail = _load_settings()
            if mail.get("bolna_api_key") and mail.get("phone"):
                cfg.setdefault("api_key", mail["bolna_api_key"])
                cfg.setdefault("phone", mail["phone"])
        except Exception:
            pass
    return cfg


def save(cfg: dict, home: Path | None = None) -> Path:
    p = config_path(home)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, p)
    return p


def configured(home: Path | None = None) -> bool:
    c = load(home)
    return bool(c.get("api_key")) and bool(E164.match(str(c.get("phone", ""))))


def describe(home: Path | None = None) -> dict:
    """Safe to print: never includes the key."""
    c = load(home)
    phone = str(c.get("phone", ""))
    return {"configured": configured(home), "has_key": bool(c.get("api_key")),
            "phone": (phone[:3] + "…" + phone[-2:]) if len(phone) > 6 else "",
            "agent": bool(c.get("agent_id")), "alerts": c.get("alerts", {"mail": True, "min_level": "high"}),
            "file": str(config_path(home))}


def _urlopen(req: urllib.request.Request, timeout: float):
    return urllib.request.urlopen(req, timeout=timeout)


def _call_api(method: str, path: str, key: str, body: dict | None, opener: Opener | None, timeout: float = 30) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        with (opener or _urlopen)(req, timeout) as r:
            out = json.loads(r.read().decode("utf-8") or "{}")
        return out if isinstance(out, dict) else {}
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Bolna returned HTTP {exc.code} for {method} {path}") from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise RuntimeError(f"Bolna request failed: {type(exc).__name__}") from None


def agent_body() -> dict:
    return {"agent_config": {
        "agent_name": "Ivy (Provenant security)",
        "agent_welcome_message": "Hi, it's Ivy from Provenant, your AI security guard. Got a moment?",
        "tasks": [{
            "task_type": "conversation",
            "toolchain": {"execution": "sequential", "pipelines": [["transcriber", "llm", "synthesizer"]]},
            "tools_config": {
                "llm_agent": {"agent_type": "simple_llm_agent", "agent_flow_type": "streaming",
                              "llm_config": {"provider": "openai", "model": "gpt-4.1-mini", "max_tokens": 120, "temperature": 0.3}},
                "transcriber": {"provider": "deepgram", "model": "nova-3", "language": "en", "stream": True,
                                "encoding": "linear16", "sampling_rate": 16000, "endpointing": 250},
                "synthesizer": {"provider": "deepgram", "provider_config": {"voice": "Andromeda", "voice_id": "andromeda-en",
                                                                             "model": "aura-2"}, "stream": True, "audio_format": "wav"},
                "input": {"provider": "plivo", "format": "wav"}, "output": {"provider": "plivo", "format": "wav"}},
            "task_config": {"call_terminate": 480, "hangup_after_silence": 15}}]},
        "agent_prompts": {"task_1": {"system_prompt": "{task}"}}}


def ensure_agent(cfg: dict, opener: Opener | None = None, home: Path | None = None) -> str:
    if cfg.get("agent_id") and cfg.get("agent_version") == AGENT_VERSION:
        return str(cfg["agent_id"])
    out = _call_api("POST", "/v2/agent", cfg["api_key"], agent_body(), opener)
    aid = out.get("agent_id")
    if not aid:
        raise RuntimeError("Bolna did not return an agent id")
    cfg["agent_id"] = aid
    try:
        raw = json.loads(config_path(home).read_text(encoding="utf-8"))
        raw = raw if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        raw = {}
    raw["agent_id"] = aid                              # only the agent id is added; env-var secrets stay in the env
    raw["agent_version"] = AGENT_VERSION
    save(raw, home)
    return str(aid)


def run_call(task: str, timeout_sec: int = 300, opener: Opener | None = None, home: Path | None = None,
             sleep: Callable[[float], None] = time.sleep) -> dict:
    """Place one call and wait for the end. Returns {execution_id, status, voicemail, error, transcript}.
    Every failure becomes a result with status 'error' or 'not_configured'; nothing here can approve anything."""
    cfg = load(home)
    if not (cfg.get("api_key") and E164.match(str(cfg.get("phone", "")))):
        return {"status": "not_configured", "error": "run `provenant phone setup` (Bolna API key + your phone number)"}
    try:
        agent_id = ensure_agent(cfg, opener, home)
        started = _call_api("POST", "/call", cfg["api_key"],
                            {"agent_id": agent_id, "recipient_phone_number": cfg["phone"],
                             "user_data": {"task": PERSONA + "\n" + task}, "bypass_call_guardrails": True}, opener)
        eid = started.get("execution_id")
        if not eid:
            return {"status": "error", "error": "Bolna did not return an execution id"}
        deadline = time.monotonic() + timeout_sec
        c: dict = {}
        while True:
            sleep(5)
            c = _call_api("GET", f"/executions/{eid}", cfg["api_key"], None, opener)
            if c.get("status") in FINAL or time.monotonic() > deadline:
                break
        return {"execution_id": eid, "status": c.get("status", "unknown"), "voicemail": c.get("answered_by_voice_mail"),
                "error": c.get("error_message"), "transcript": c.get("transcript")}
    except RuntimeError as exc:
        return {"status": "error", "error": str(exc)}
