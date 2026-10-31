"""Per-mail screening for anything an agent reads through a mail connector (Gmail MCP server and the like).

Every mail that comes back in a tool result is parsed, scored from deterministic signals, written to the audit
log as a verdict (sender, subject, level, reasons; never the body), and, when it is high risk, makes the
session distrust it (later side effects need a human) and can alert the user by phone (alert.py path below).

This is a screening aid, not a promise: the signals are heuristics (look-alike domains, link/text mismatch,
urgency + credential asks, risky attachments, failed SPF/DKIM/DMARC, reply-to mismatch, prompt injection in
the body). Provenant never blocks reading a mail and never decides on the user's behalf; the model is not asked.
"""
from __future__ import annotations

import base64
import json
import re
import threading
from email.utils import parseaddr
from typing import Any, Callable
from urllib.parse import urlsplit

from .detectors import scan_injection
from .normalize import canonical, obfuscation_signals, views

LEVELS = ("low", "medium", "high")
MEDIUM, HIGH = 30, 60
MAIL_TOOL = re.compile(r"(gmail|mail|inbox|imap|outlook|message|thread|email)", re.I)
BRANDS = {"paypal": "paypal.com", "google": "google.com", "microsoft": "microsoft.com", "apple": "apple.com",
          "amazon": "amazon.com", "netflix": "netflix.com", "facebook": "facebook.com", "instagram": "instagram.com",
          "hdfc": "hdfcbank.com", "icici": "icicibank.com", "sbi": "sbi.co.in", "axis": "axisbank.com", "paytm": "paytm.com",
          "phonepe": "phonepe.com", "dhl": "dhl.com", "fedex": "fedex.com", "linkedin": "linkedin.com",
          "github": "github.com", "docusign": "docusign.com", "irs": "irs.gov", "uber": "uber.com"}
FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me", "protonmail.com", "aol.com", "rediffmail.com"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc"}
RISKY_EXT = (".exe", ".scr", ".js", ".jse", ".vbs", ".bat", ".cmd", ".lnk", ".iso", ".img", ".msi", ".jar", ".ps1",
             ".hta", ".docm", ".xlsm", ".pptm", ".html", ".htm", ".svg")
URGENCY = re.compile(r"(urgent|immediately|within 24 hours|final notice|last warning|act now|account (?:will be )?(?:suspended|"
                     r"locked|closed|disabled)|suspend(?:ed|ion)|verify your (?:account|identity)|unusual (?:sign|activity)|"
                     r"expires? (?:today|soon)|avoid (?:a )?(?:penalty|fine)|turant|jaldi|abhi|खाता|तुरंत|ತಕ್ಷಣ)", re.I)
CRED_ASK = re.compile(r"(password|passcode|otp|one[- ]time (?:code|password)|cvv|pin\b|card number|net ?banking|login details|"
                      r"social security|ssn|aadhaar|seed phrase|recovery phrase|private key|gift ?cards?|wire transfer|"
                      r"bank details|update (?:your )?(?:payment|billing)|confirm your (?:account|identity|details))", re.I)
MONEY_PRESSURE = re.compile(r"(gift ?cards?|bitcoin|crypto(?:currency)? wallet|western union|wire (?:the )?funds|new bank (?:account|details)|"
                            r"change(?:d)? (?:of )?bank|do not (?:tell|discuss|call)|keep this (?:confidential|secret))", re.I)
URL = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
HREF = re.compile(r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S)
MDLINK = re.compile(r"\[([^\]]{3,200})\]\((https?://[^)\s]+)\)")
TAG = re.compile(r"<[^>]+>")


def _lev(score: int) -> str:
    return "high" if score >= HIGH else "medium" if score >= MEDIUM else "low"


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">. ") if "@" in addr else ""


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "gov", "ac", "net") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _skeletons(s: str) -> set[str]:
    base = s.lower().replace("rn", "m").replace("vv", "w")
    return {base.translate(str.maketrans("0!|5$3", "oilsse") | {ord("1"): ch}) for ch in "li"}


def _lookalike(host: str) -> str | None:
    reg = _registrable(host)
    if reg.startswith("xn--") or ".xn--" in "." + host:
        return f"punycode domain {host}"
    label = reg.split(".")[0]
    tokens = set(re.split(r"[-.]", host))
    for brand, real in BRANDS.items():
        if reg == real or label == brand:
            continue
        if brand in tokens or any(brand in _skeletons(t) for t in tokens | {label}):
            return f"{host} imitates {real}"
    return None


# --- extraction ------------------------------------------------------------------------------------------
def _b64(s: str) -> str:
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")
    except (ValueError, TypeError):
        return ""


def _header_map(h: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(h, list):
        for e in h:
            if isinstance(e, dict) and "name" in e:
                out.setdefault(str(e["name"]).lower(), str(e.get("value", "")))
    elif isinstance(h, dict):
        out = {str(k).lower(): str(v) for k, v in h.items()}
    return out


def _body_of(d: dict) -> str:
    parts = []
    for k in ("body", "text", "textBody", "plain", "html", "htmlBody", "content", "snippet", "preview"):
        v = d.get(k)
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, dict) and isinstance(v.get("data"), str):
            parts.append(_b64(v["data"]))
    pl = d.get("payload")
    if isinstance(pl, dict):
        stack = [pl]
        while stack:
            p = stack.pop()
            if isinstance(p.get("body"), dict) and isinstance(p["body"].get("data"), str):
                parts.append(_b64(p["body"]["data"]))
            stack += [x for x in p.get("parts", []) if isinstance(x, dict)]
    return "\n".join(x for x in parts if x)


def _attachments(d: dict) -> list[str]:
    names: list[str] = []
    for k in ("attachments", "files"):
        for a in d.get(k) or []:
            n = a.get("filename") or a.get("name") if isinstance(a, dict) else a
            if isinstance(n, str):
                names.append(n)
    stack = [d.get("payload")] if isinstance(d.get("payload"), dict) else []
    while stack:
        p = stack.pop()
        if isinstance(p.get("filename"), str) and p["filename"]:
            names.append(p["filename"])
        stack += [x for x in p.get("parts", []) if isinstance(x, dict)]
    return names


def _from_dict(d: dict) -> dict | None:
    h = _header_map(d.get("headers") or (d.get("payload") or {}).get("headers"))
    sender = str(d.get("from") or d.get("sender") or h.get("from") or "")
    subject = str(d.get("subject") or h.get("subject") or "")
    body = _body_of(d)
    if not (sender or subject) or not (sender or body):
        return None
    return {"id": str(d.get("id") or d.get("messageId") or h.get("message-id") or "")[:80], "from": sender, "subject": subject,
            "reply_to": str(d.get("replyTo") or d.get("reply_to") or h.get("reply-to") or ""),
            "auth": str(h.get("authentication-results", "")) + " " + str(h.get("received-spf", "")),
            "body": body, "attachments": _attachments(d)}


_RFC = re.compile(r"(?im)^(?=from:\s)")


def _from_text(text: str) -> list[dict]:
    mails = []
    for chunk in _RFC.split(text):
        m = re.match(r"(?is)from:\s*(.+?)\r?\n(.*)", chunk)
        if not m:
            continue
        head, rest = m.group(2).split("\n\n", 1) if "\n\n" in m.group(2) else (m.group(2), "")
        get = lambda n: (re.search(rf"(?im)^{n}:\s*(.+)$", head) or [None, ""])[1].strip()
        mails.append({"id": get("message-id")[:80], "from": m.group(1).strip(), "subject": get("subject"),
                      "reply_to": get("reply-to"), "auth": get("authentication-results") + " " + get("received-spf"),
                      "body": rest or head, "attachments": re.findall(r'filename="?([^";\r\n]+)', chunk)})
    return mails


def extract_mails(output: Any, limit: int = 200) -> list[dict]:
    """Find mails in a tool result: JSON objects (Gmail API or simple shapes), JSON inside text blocks, or RFC-style text."""
    found: list[dict] = []
    texts: list[str] = []

    def walk(o: Any, depth: int = 0) -> None:
        if depth > 8 or len(found) >= limit:
            return
        if isinstance(o, dict):
            m = _from_dict(o)
            if m:
                found.append(m)
                return
            if o.get("type") == "text" and isinstance(o.get("text"), str):
                s = o["text"]
                try:
                    walk(json.loads(s), depth + 1)
                    return
                except ValueError:
                    texts.append(s)
                    return
            for v in o.values():
                walk(v, depth + 1)
        elif isinstance(o, list):
            for v in o:
                walk(v, depth + 1)
        elif isinstance(o, str) and depth:
            try:
                if o.lstrip()[:1] in "[{":
                    walk(json.loads(o), depth + 1)
                    return
            except ValueError:
                pass
            texts.append(o)

    walk(output)
    if not found:
        for t in texts or ([output] if isinstance(output, str) else []):
            found += _from_text(t)
    return found[:limit]


# --- scoring ---------------------------------------------------------------------------------------------
def score_mail(m: dict) -> dict:
    sig: list[tuple[int, str, str]] = []                       # (weight, code, reason)
    name, addr = parseaddr(m.get("from", ""))
    dom = _domain(addr)
    body = m.get("body", "") or ""
    subject = m.get("subject", "") or ""
    text = f"{subject}\n{body}"

    if not addr or not dom:
        sig.append((15, "no_sender", "no readable sender address"))
    for brand, real in BRANDS.items():
        if re.search(rf"\b{brand}\b", f"{name} {subject}".lower()) and dom and _registrable(dom) != real and _registrable(dom).split(".")[0] != brand:
            sig.append((40, "display_name_spoof", f"sender name mentions {brand} but the address is @{dom}"))
            break
    la = _lookalike(dom) if dom else None
    if la:
        sig.append((45, "lookalike_domain", f"sender domain: {la}"))
    rt = parseaddr(m.get("reply_to", ""))[1]
    if rt and dom and _domain(rt) and _registrable(_domain(rt)) != _registrable(dom):
        sig.append((25, "reply_to_mismatch", f"replies go to @{_domain(rt)}, not @{dom}"))
    auth = (m.get("auth") or "").lower()
    if re.search(r"\b(spf|dkim|dmarc)=(fail|softfail|none|permerror|temperror)", auth):
        sig.append((25, "auth_fail", "SPF/DKIM/DMARC did not pass"))

    urgent, ask = bool(URGENCY.search(text)), bool(CRED_ASK.search(text))
    if urgent:
        sig.append((12, "urgency", "pressure or urgency wording"))
    if ask:
        sig.append((18, "credential_ask", "asks for a password, code, card, ID or payment detail"))
    if urgent and ask:
        sig.append((15, "urgent_credential_ask", "urgency combined with a credential or payment request"))
    if MONEY_PRESSURE.search(text):
        sig.append((30, "payment_pressure", "gift cards, crypto, changed bank details or secrecy"))
    if dom in FREE_MAIL and re.search(r"(bank|payroll|security team|support team|ceo|director|invoice|hr\b)", f"{name} {subject}", re.I):
        sig.append((15, "free_mail_authority", f"authority claimed from a free mail address (@{dom})"))

    links = [(t, u) for u, t in HREF.findall(body)] + [(t, u) for t, u in MDLINK.findall(body)]
    for t, u in links:
        shown = URL.search(TAG.sub("", t))
        if shown and _registrable(_host(shown.group(0))) != _registrable(_host(u)):
            sig.append((40, "link_text_mismatch", f"link text shows {_host(shown.group(0))} but goes to {_host(u)}"))
            break
    hosts = {_host(u) for u in URL.findall(body)} | {_host(u) for _, u in links}
    hosts.discard("")
    if any(h in SHORTENERS for h in hosts):
        sig.append((15, "shortener", "a shortened link hides the destination"))
    if any(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}|0x[0-9a-f]+|\d{8,10}", h) for h in hosts):
        sig.append((30, "ip_link", "a link points to a raw IP address"))
    if re.search(r"https?://[^/\s]*@", body):
        sig.append((30, "userinfo_link", "a link hides its real host behind user@host"))
    for h in hosts:
        la2 = _lookalike(h)
        if la2:
            sig.append((35, "lookalike_link", f"link: {la2}"))
            break
    for a in m.get("attachments", []):
        low = a.lower()
        if low.endswith(RISKY_EXT) or re.search(r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|js|bat|cmd|lnk|html?)$", low):
            sig.append((35, "risky_attachment", f"attachment '{a[:60]}' can run code"))
            break

    inj = []
    for v in views(text):
        inj += [f["label"] for f in scan_injection(canonical(v))]
    inj += [f["label"] for f in obfuscation_signals(text, scan_injection)]
    if inj:
        sig.append((60, "prompt_injection", "the mail tries to instruct the AI agent: " + ", ".join(sorted(set(inj))[:3])))

    seen, reasons, total = set(), [], 0
    for w, code, why in sorted(sig, key=lambda s: -s[0]):
        if code in seen:
            continue
        seen.add(code)
        total += w
        reasons.append({"code": code, "reason": why})
    score = min(100, total)
    return {"id": m.get("id", ""), "from": (name + " <" + addr + ">" if name and addr else addr or m.get("from", ""))[:120],
            "subject": subject[:120], "score": score, "level": _lev(score), "signals": reasons[:8]}


def analyze_output(output: Any) -> list[dict]:
    return [score_mail(m) for m in extract_mails(output)]


def looks_like_mail_tool(tool: str) -> bool:
    return bool(MAIL_TOOL.search(tool.rsplit("__", 1)[-1])) or bool(MAIL_TOOL.search(tool))


# --- alerts ----------------------------------------------------------------------------------------------
def alert_task(v: dict) -> str:
    why = "; ".join(s["reason"] for s in v["signals"][:3])
    return ("Phone call purpose: tell the user about one suspicious email that their AI agent just read. This is a heads-up, "
            "not an approval request.\n"
            f"Sender: {v['from'][:80]}. Subject: {v['subject'][:80]}. Provenant risk: {v['level']} ({v['score']} of 100). "
            f"Why: {why[:300]}.\n"
            "Say this in two or three short sentences, plainly. Tell them Provenant has not acted on the mail and that "
            "sends, forwards and deletes from this session now need their approval. Tell them not to click links or open "
            "attachments from it. Do not read out long addresses or links. Ask if they want anything else, then end the call.")


_LEVEL_RANK = {l: i for i, l in enumerate(LEVELS)}
_alerted: set[str] = set()


def maybe_alert(verdicts: list[dict], cfg: dict | None = None, caller: Callable[[str], dict] | None = None,
                background: bool = True) -> list[str]:
    """Phone the user about high-risk mail when phone alerts are configured. Never blocks the tool result, never
    raises, and calls at most once per mail id and at most 3 mails per batch."""
    from . import bolna
    cfg = cfg if cfg is not None else bolna.load()
    alerts = cfg.get("alerts") or {}
    if alerts.get("mail", True) is False or not (cfg.get("api_key") and cfg.get("phone")):
        return []
    floor = _LEVEL_RANK.get(str(alerts.get("min_level", "high")), 2)
    todo = [v for v in verdicts if _LEVEL_RANK[v["level"]] >= floor]
    sent = []
    for v in todo[:3]:
        key = v["id"] or v["from"] + v["subject"]
        if key in _alerted:
            continue
        _alerted.add(key)
        task = alert_task(v)
        run = caller or (lambda t: bolna.run_call(t, timeout_sec=240))
        if background:
            threading.Thread(target=lambda t=task: _safe(run, t), daemon=True).start()
        else:
            _safe(run, task)
        sent.append(key)
    return sent


def _safe(run: Callable[[str], dict], task: str) -> None:
    try:
        run(task)
    except Exception:
        pass
