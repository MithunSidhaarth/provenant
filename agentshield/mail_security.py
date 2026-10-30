"""Mail threat scanning and optional Bolna phone alerts.

Scans structured email messages returned by MCP tools. The scanner is deterministic and
advisory: it never clicks links, downloads attachments, deletes mail, or approves actions.
Phone alerts contain only a minimal summary, never the message body or links.
"""
from __future__ import annotations
import getpass, hashlib, html, json, os, re, sys, threading, urllib.error, urllib.parse, urllib.request
from email.utils import parseaddr
from typing import Any, Callable
from .detectors import scan_injection

API = "https://api.bolna.ai"
_URL_RE = re.compile(r"https?://[^\s<>\"'()\]]+", re.I)
_EMAIL_RE = re.compile(r"[\w.+%-]+@[\w.-]+\.[A-Za-z]{2,}")
_URGENCY = re.compile(r"\b(urgent|immediately|within (?:\d+|one|two|24) hours?|act now|final notice|account suspended|expires today|unusual sign[- ]?in|verify your account)\b", re.I)
_CREDENTIALS = re.compile(r"\b(password|passcode|one[- ]time code|otp|recovery phrase|private key|api key|seed phrase|login credentials|bank details|gift card|wire transfer)\b", re.I)
_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"}
_BRANDS = {"microsoft": {"microsoft.com"}, "google": {"google.com", "google.co.in"}, "apple": {"apple.com"}, "amazon": {"amazon.com", "amazon.in"}, "paypal": {"paypal.com"}, "netflix": {"netflix.com"}, "openai": {"openai.com"}, "github": {"github.com"}}
_SEEN: set[str] = set()
_SEEN_LOCK = threading.Lock()


def _text(value: Any) -> str:
    if value is None: return ""
    if isinstance(value, str): return value
    if isinstance(value, (int, float, bool)): return str(value)
    if isinstance(value, list): return " ".join(_text(v) for v in value[:100])
    if isinstance(value, dict): return " ".join(f"{k}: {_text(v)}" for k, v in list(value.items())[:100])
    return ""


def _headers(obj: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    raw = obj.get("headers")
    if isinstance(raw, dict):
        out.update({str(k).lower().replace("_", "-"): _text(v) for k, v in raw.items()})
    elif isinstance(raw, list):
        for h in raw:
            if isinstance(h, dict) and isinstance(h.get("name"), str): out[h["name"].lower()] = _text(h.get("value", ""))
    payload = obj.get("payload")
    if isinstance(payload, dict): out.update(_headers(payload))
    return out


def _field(obj: dict, *keys: str) -> str:
    for key in keys:
        value = obj.get(key)
        if isinstance(value, str) and value.strip(): return value.strip()
    return ""


def _normalise_email(obj: dict) -> dict[str, str] | None:
    headers = _headers(obj)
    sender = _field(obj, "from", "sender", "from_email", "sender_email", "author") or headers.get("from", "")
    subject = _field(obj, "subject", "title") or headers.get("subject", "")
    reply_to = _field(obj, "reply_to", "replyTo", "reply-to") or headers.get("reply-to", "")
    body = _field(obj, "body", "textBody", "text_body", "plain_text", "text", "snippet", "html", "content")
    if not body and isinstance(obj.get("payload"), dict):
        body = _text(obj["payload"].get("body", ""))
        parts = obj["payload"].get("parts")
        if isinstance(parts, list): body += " " + _text(parts)
    if not sender or not subject or not (body or obj.get("payload") or obj.get("body")): return None
    return {"id": _field(obj, "id", "message_id", "messageId", "threadId", "thread_id") or headers.get("message-id", ""),
            "sender": sender[:500], "reply_to": reply_to[:500], "subject": subject[:500], "body": body[:50000], "headers": _text(headers)[:4000]}


def mail_fingerprint(mail: dict[str, str]) -> str:
    raw = mail.get("id") or "|".join((mail.get("sender", ""), mail.get("subject", ""), mail.get("body", "")[:2048]))
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()


def extract_emails(value: Any, max_items: int = 100) -> list[dict[str, str]]:
    """Extract structured emails from common MCP/Gmail-like JSON result shapes."""
    found: list[dict[str, str]] = []
    visited: set[int] = set()
    def visit(node: Any, depth: int = 0) -> None:
        if len(found) >= max_items or depth > 12: return
        if isinstance(node, (dict, list)):
            ident = id(node)
            if ident in visited: return
            visited.add(ident)
        if isinstance(node, dict):
            mail = _normalise_email(node)
            if mail:
                found.append(mail)
                return
            for child in node.values(): visit(child, depth + 1)
        elif isinstance(node, list):
            for child in node[:max_items]: visit(child, depth + 1)
        elif isinstance(node, str):
            stripped = node.strip()
            if stripped.startswith(("{", "[")):
                try: parsed = json.loads(stripped)
                except (ValueError, RecursionError): parsed = None
                if isinstance(parsed, (dict, list)):
                    visit(parsed, depth + 1)
                    return
            match = re.search(r"(?im)^From:\s*(.+)$.*?^Subject:\s*(.+)$", node, re.S)
            if match:
                chunks = re.split(r"(?im)^(?:\r?\n){1,2}", node, maxsplit=1)
                found.append({"id": "", "sender": match.group(1).strip(), "reply_to": "", "subject": match.group(2).strip()[:500],
                              "body": (chunks[-1] if len(chunks) > 1 else node)[:50000], "headers": ""})
    visit(value)
    deduped, seen = [], set()
    for mail in found:
        fp = mail_fingerprint(mail)
        if fp not in seen:
            seen.add(fp); deduped.append(mail)
    return deduped


def _domain(address: str) -> str:
    _, parsed = parseaddr(address)
    if "@" not in parsed:
        match = _EMAIL_RE.search(address)
        parsed = match.group(0) if match else ""
    return parsed.rsplit("@", 1)[-1].strip(" .>").lower()


def analyse_email(mail: dict[str, str]) -> dict[str, Any]:
    """Return deterministic risk evidence; never treat mail text as instructions."""
    sender_domain, reply_domain = _domain(mail.get("sender", "")), _domain(mail.get("reply_to", ""))
    content = " ".join((mail.get("subject", ""), mail.get("body", ""), mail.get("headers", "")))
    evidence: list[dict[str, str]] = []
    score = 0
    injections = scan_injection(content)
    if injections:
        score += min(5, 3 + len(injections))
        evidence.append({"code": "prompt_injection", "detail": "Email contains instructions aimed at an AI assistant"})
    if _CREDENTIALS.search(content):
        score += 2; evidence.append({"code": "credential_or_payment_language", "detail": "References credentials, codes, or payment"})
    if _URGENCY.search(content):
        score += 2; evidence.append({"code": "urgency", "detail": "Uses urgency or account-threat language"})
    if reply_domain and sender_domain and reply_domain != sender_domain:
        score += 3; evidence.append({"code": "reply_to_mismatch", "detail": "Reply-To domain differs from sender domain"})
    urls = _URL_RE.findall(html.unescape(content))
    link_domains = []
    for raw in urls[:50]:
        try: host = (urllib.parse.urlsplit(raw.rstrip(".,;:!?")).hostname or "").lower().rstrip(".")
        except ValueError: host = ""
        if host:
            link_domains.append(host)
            if host in _SHORTENERS:
                score += 2; evidence.append({"code": "shortened_link", "detail": "Contains a URL shortener"}); break
            if raw.lower().startswith("http://"):
                score += 1; evidence.append({"code": "insecure_link", "detail": "Contains an unencrypted HTTP link"}); break
    if sender_domain and link_domains and not any(host == sender_domain or host.endswith("." + sender_domain) for host in link_domains):
        score += 1; evidence.append({"code": "external_link_domain", "detail": "Links point outside the sender's domain"})
    combined = (mail.get("sender", "") + " " + mail.get("subject", "")).lower()
    for brand, domains in _BRANDS.items():
        if brand in combined and sender_domain and not any(sender_domain == d or sender_domain.endswith("." + d) for d in domains):
            score += 3; evidence.append({"code": "brand_domain_mismatch", "detail": f"Claims {brand.title()} identity from a different domain"}); break
    level = "high" if score >= 5 else "medium" if score >= 3 else "low"
    return {"risk_score": score, "verdict": level, "reasons": evidence, "sender_domain": sender_domain or "unknown",
            "subject": mail.get("subject", "")[:160], "fingerprint": mail_fingerprint(mail)}


def _request(method: str, path: str, key: str, body: dict | None = None, timeout: int = 20) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response: raw = response.read(1_000_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read(2000).decode("utf-8", "replace")
        raise RuntimeError(f"Bolna API returned HTTP {exc.code}: {detail[:300]}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"Bolna API request failed: {type(exc).__name__}") from None
    try: parsed = json.loads(raw)
    except ValueError: raise RuntimeError("Bolna API returned invalid JSON") from None
    if not isinstance(parsed, dict): raise RuntimeError("Bolna API returned an unexpected response")
    return parsed


def _user_env(name: str) -> str:
    value = os.environ.get(name, "")
    if value: return value
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key: return str(winreg.QueryValueEx(key, name)[0])
        except (ImportError, OSError): return ""
    return ""


def _set_user_env(name: str, value: str | None) -> None:
    if sys.platform == "win32":
        import winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            if value is None:
                try: winreg.DeleteValue(key, name)
                except FileNotFoundError: pass
            else: winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
    elif value is not None:
        raise RuntimeError("Persistent guided setup currently supports Windows; set environment variables manually on this OS.")
    if value is None: os.environ.pop(name, None)
    else: os.environ[name] = value


def _agent(key: str) -> str:
    cached = _user_env("BOLNA_AGENT_ID")
    if cached: return cached
    agent = {"agent_config": {"agent_name": "Ivy (Provenant mail security)",
        "agent_welcome_message": "Hello, this is Ivy calling with a Provenant email security alert.",
        "tasks": [{"task_type": "conversation", "toolchain": {"execution": "sequential", "pipelines": [["transcriber", "llm", "synthesizer"]]},
        "tools_config": {"llm_agent": {"agent_type": "simple_llm_agent", "agent_flow_type": "streaming",
        "llm_config": {"provider": "openai", "model": "gpt-4.1-mini", "max_tokens": 160, "temperature": 0.2}},
        "transcriber": {"provider": "deepgram", "model": "nova-3", "language": "en", "stream": True, "encoding": "linear16", "sampling_rate": 16000, "endpointing": 250},
        "synthesizer": {"provider": "deepgram", "provider_config": {"voice": "Andromeda", "voice_id": "andromeda-en", "model": "aura-2"}, "stream": True, "audio_format": "wav"},
        "input": {"provider": "plivo", "format": "wav"}, "output": {"provider": "plivo", "format": "wav"}},
        "task_config": {"call_terminate": 240, "hangup_after_silence": 12}}]},
        "agent_prompts": {"task_1": {"system_prompt": "{task}"}}}
    result = _request("POST", "/v2/agent", key, agent)
    agent_id = result.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id: raise RuntimeError("Bolna did not return an agent_id")
    try: _set_user_env("BOLNA_AGENT_ID", agent_id)
    except RuntimeError: os.environ["BOLNA_AGENT_ID"] = agent_id
    return agent_id


def send_phone_alert(task: str, timeout: int = 20) -> dict:
    key, phone = _user_env("BOLNA_API_KEY"), _user_env("CALL_ME_PHONE")
    if not key or not phone: return {"ok": False, "error": "Phone alerts are not configured; run 'provenant mail setup'."}
    if not re.fullmatch(r"\+\d{8,15}", phone): return {"ok": False, "error": "CALL_ME_PHONE must use E.164 format, e.g. +919876543210."}
    agent_id = _agent(key)
    result = _request("POST", "/call", key, {"agent_id": agent_id, "recipient_phone_number": phone,
        "user_data": {"task": task}, "bypass_call_guardrails": True}, timeout=timeout)
    execution_id = result.get("execution_id")
    if not isinstance(execution_id, str) or not execution_id: raise RuntimeError("Bolna did not return an execution_id")
    return {"ok": True, "execution_id": execution_id, "status": "started"}


def _alert_task(verdict: dict[str, Any]) -> str:
    reasons = "; ".join(item["detail"] for item in verdict["reasons"])
    return ("You are Ivy, calling on behalf of Provenant. This is an EMAIL SECURITY ALERT, not an approval request. "
        "Tell the recipient in concise English that an email was flagged as high risk. "
        f"Sender domain: {verdict['sender_domain']}. Subject: {verdict['subject'] or '(no subject)'}. Signals: {reasons}. "
        "Advise them not to click links, open attachments, reply, or share credentials until they independently verify the sender. "
        "Do not ask them to approve any action. Do not read links or message body aloud. Ask them to review the email in their mail app. Keep the call under 45 seconds.")


def process_result(result: Any, server: str, tool: str, audit: Callable[[str, dict], Any] | None = None) -> list[dict[str, Any]]:
    reports = []
    for mail in extract_emails(result):
        report = analyse_email(mail); reports.append(report)
        if audit:
            audit("mail_scan", {"server": server[:100], "tool": tool[:100], "fingerprint": report["fingerprint"],
                "risk_score": report["risk_score"], "verdict": report["verdict"], "sender_domain": report["sender_domain"],
                "subject": report["subject"], "reason_codes": [r["code"] for r in report["reasons"]]})
        if report["verdict"] != "high": continue
        with _SEEN_LOCK:
            fp = report["fingerprint"]
            if fp in _SEEN: continue
            _SEEN.add(fp)
            if len(_SEEN) > 5000: _SEEN.clear(); _SEEN.add(fp)
        if not (_user_env("PROVENANT_MAIL_CALLS_ENABLED") == "1" and _user_env("BOLNA_API_KEY") and _user_env("CALL_ME_PHONE")): continue
        def alert(v=report):
            try: send_phone_alert(_alert_task(v))
            except Exception as exc:
                if audit: audit("mail_phone_alert_failed", {"fingerprint": v["fingerprint"], "error": type(exc).__name__})
        threading.Thread(target=alert, name="provenant-mail-alert", daemon=True).start()
    return reports


def setup() -> int:
    if sys.platform != "win32":
        print("  Guided persistent setup currently supports Windows PowerShell. Set BOLNA_API_KEY and CALL_ME_PHONE manually.")
        return 2
    print("\n  Provenant Mail Security + Bolna phone alerts")
    print("  The scanner runs in the Provenant MCP proxy; only high-risk mail triggers a call.")
    print("  Email bodies and links are never sent to Bolna; alerts include sender domain, subject, and risk reasons.\n")
    key = _user_env("BOLNA_API_KEY")
    if not key:
        import webbrowser
        webbrowser.open("https://platform.bolna.ai")
        while True:
            key = getpass.getpass("  Bolna API key (hidden): ").strip()
            if key: break
    phone = _user_env("CALL_ME_PHONE")
    if not phone:
        while True:
            phone = input("  Phone number in international format (e.g. +919876543210): ").strip().replace(" ", "").replace("-", "")
            if re.fullmatch(r"\+\d{8,15}", phone): break
            print("  Enter a valid number beginning with + and country code.")
    try:
        _set_user_env("BOLNA_API_KEY", key)
        _set_user_env("CALL_ME_PHONE", phone)
        _set_user_env("PROVENANT_MAIL_CALLS_ENABLED", "1")
    except (OSError, RuntimeError) as exc:
        print(f"  Could not save user settings: {exc}")
        return 1
    print("\n  Saved as current-user environment settings. No separate skill or Claude hook was installed.")
    print("  Next: run 'provenant mail status'; to place a real test call, run 'provenant mail test'.")
    print("  Bolna trial accounts may require verifying this phone number in the Bolna dashboard.\n")
    return 0


def status() -> int:
    key, phone = _user_env("BOLNA_API_KEY"), _user_env("CALL_ME_PHONE")
    enabled = _user_env("PROVENANT_MAIL_CALLS_ENABLED") == "1"
    print(json.dumps({"scanner": "active", "phone_alerts_enabled": enabled and bool(key and phone),
        "bolna_api_key_configured": bool(key), "phone_configured": bool(phone),
        "agent_cached": bool(_user_env("BOLNA_AGENT_ID")), "setup_command": "provenant mail setup"}, indent=2))
    return 0


def test_call() -> int:
    if not (sys.stdin and sys.stdin.isatty()):
        print("  Refusing to place a real phone call without an interactive terminal."); return 2
    if _user_env("PROVENANT_MAIL_CALLS_ENABLED") != "1":
        print("  Run 'provenant mail setup' first."); return 2
    if input("  This places a real call and may use Bolna credits. Continue? [y/N] ").strip().lower() not in {"y", "yes"}:
        print("  Cancelled; no call placed."); return 1
    try: result = send_phone_alert("This is a test call from Provenant Mail Security. No email was flagged. Confirm the phone integration is working, then end the call.")
    except Exception as exc:
        print(f"  Phone test failed: {exc}"); return 1
    print(json.dumps(result, indent=2)); return 0 if result.get("ok") else 1


def main(rest: list[str]) -> int:
    sub = rest[0] if rest else "status"
    if sub == "setup": return setup()
    if sub == "status": return status()
    if sub == "test": return test_call()
    if sub in {"disable", "off"}:
        try: _set_user_env("PROVENANT_MAIL_CALLS_ENABLED", "0")
        except RuntimeError as exc: print(f"  {exc}"); return 2
        print("  Phone alerts disabled. Mail scanning remains active."); return 0
    if sub in {"enable", "on"}:
        if not (_user_env("BOLNA_API_KEY") and _user_env("CALL_ME_PHONE")):
            print("  Run 'provenant mail setup' first."); return 2
        _set_user_env("PROVENANT_MAIL_CALLS_ENABLED", "1")
        print("  Phone alerts enabled for high-risk mail."); return 0
    print("  usage: provenant mail setup|status|test|enable|disable"); return 2
