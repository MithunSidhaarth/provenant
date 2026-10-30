"""Deterministic content detectors.

These produce *evidence*. They are deliberately not the security boundary: the boundary is
the permission, boundary, provenance and approval rules in policy.py, which hold even if an
injection is phrased in a way these patterns miss.
"""
from __future__ import annotations

import re

INJECTION_PATTERNS = [
    (r"ignore (all )?(any )?(previous|prior|above) (instructions|rules|directions)", "override-instructions"),
    (r"disregard (the )?(system|previous|prior) (prompt|instructions|policy)", "override-instructions"),
    (r"you are now|new instructions|system override|developer mode", "role-hijack"),
    (r"\bassistant[_ ]?(action|instruction)s?\s*:", "embedded-tool-directive"),
    (r"\b(send|forward|email) (it|this|them|the \w+) to\b", "exfiltration-request"),
    (r"do not (tell|inform|notify) (the )?user", "concealment"),
    (r"(get_secret|vault|api[_ ]?key|credentials?)\b.{0,40}\b(send|email|include|attach|forward)", "secret-exfiltration"),
]

SSN_RE = re.compile(r"\b9\d{2}-\d{2}-\d{4}\b|\b\d{3}-\d{2}-\d{4}\b")
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")
CANARY_RE = re.compile(r"CANARY-[A-Za-z0-9_\-]+")


def scan_injection(text: str) -> list[dict]:
    hits = []
    low = text.lower()
    for pattern, label in INJECTION_PATTERNS:
        m = re.search(pattern, low)
        if m:
            start = max(0, m.start() - 40)
            hits.append({"label": label, "match": text[m.start():m.end()],
                         "snippet": text[start:m.end() + 60].replace("\n", " ")})
    return hits


def scan_sensitive(text: str, known_secrets: dict[str, str] | None = None) -> list[dict]:
    """Find secrets and regulated data in an outbound payload."""
    hits = []
    for name, value in (known_secrets or {}).items():
        if value and value in text:
            hits.append({"type": "vault_secret", "name": name})
    for m in CANARY_RE.finditer(text):
        hits.append({"type": "canary_pattern", "match": m.group(0)[:16] + "…"})
    for m in SSN_RE.finditer(text):
        hits.append({"type": "ssn", "match": "***-**-" + m.group(0)[-4:]})
    for m in CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 16:
            hits.append({"type": "card_number", "match": "**** " + digits[-4:]})
    return hits
