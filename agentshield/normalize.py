"""Text canonicalisation for untrusted content.

Attackers hide instructions with zero-width characters, look-alike letters from other scripts,
base64/hex blobs and split fields. Before AgentShield taints or scans untrusted content it
produces *views* of it: the raw text, a canonical form (zero-width removed, homoglyphs folded,
NFKC) and any decodable base64/hex payloads. Taint tracking and injection detection run over all
views, so an encoded recipient is still recognised as coming from the document.

The simulated agent uses the same decoding to model a strong model that *understands*
obfuscated instructions; that is the worst case the gateway has to survive.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

ZERO_WIDTH_RE = re.compile("[​-‏⁠-⁤﻿­᠎]")
TAG_CHARS_RE = re.compile("[\U000e0000-\U000e007f]")

# Common Cyrillic/Greek look-alikes of Latin letters.
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "һ": "h", "ӏ": "l", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
    "τ": "t", "ρ": "p", "Ο": "O", "Α": "A", "Ε": "E", "Τ": "T",
})

B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){10,}\b")


def canonical(text: str) -> str:
    text = TAG_CHARS_RE.sub("", ZERO_WIDTH_RE.sub("", text))
    return unicodedata.normalize("NFKC", text).translate(HOMOGLYPHS)


def _printable(s: str) -> bool:
    return bool(s) and sum(ch.isprintable() or ch in "\n\t" for ch in s) / len(s) > 0.95


TAG_RUN_RE = re.compile("[\U000e0020-\U000e007e]{4,}")


def decoded_payloads(text: str) -> list[str]:
    out = []
    for m in TAG_RUN_RE.finditer(text):      # "ASCII smuggling" via invisible Unicode tag characters
        out.append("".join(chr(ord(ch) - 0xE0000) for ch in m.group(0)))
    for m in B64_RE.finditer(text):
        tok = m.group(0)
        try:
            s = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if _printable(s) and len(s) >= 8:
            out.append(s)
    for m in HEX_RE.finditer(text):
        try:
            s = bytes.fromhex(m.group(0)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _printable(s):
            out.append(s)
    return out


def obfuscation_signals(text: str, scan) -> list[dict]:
    """Obfuscation is reported only when it hides something: invisible characters always do,
    homoglyphs and encodings only when the decoded form contains injection indicators.
    (Tuned after the benign corpus showed Cyrillic names and base64 build ids as false flags.)"""
    sig = []
    if ZERO_WIDTH_RE.search(text) or TAG_CHARS_RE.search(text):
        sig.append({"label": "invisible-characters", "match": "zero-width / tag characters present", "snippet": ""})
    folded = canonical(text)
    if text.translate(HOMOGLYPHS) != text and scan(folded) and not scan(text):
        sig.append({"label": "homoglyphs", "match": "look-alike letters hide an instruction", "snippet": ""})
    for d in decoded_payloads(text) + decoded_payloads(folded):
        if scan(canonical(d)):
            sig.append({"label": "encoded-payload", "match": d[:60], "snippet": d[:120]})
    return sig


EXTRA_DECODERS = {
    "rot13": lambda t: codecs.decode(t, "rot13"),
    "reversed": lambda t: "\n".join(line[::-1] for line in t.splitlines()),
}


def views(text: str, extra: tuple[str, ...] = ()) -> list[str]:
    """Raw, canonical and decoded views of a piece of untrusted content. `extra` enables
    optional decoders (policy: canonicalisation.extra_decoders), e.g. ones the red-team loop proposes."""
    c = canonical(text)
    vs = [text]
    if c != text:
        vs.append(c)
    for d in decoded_payloads(text) + decoded_payloads(c):
        vs.append(canonical(d))
    for name in extra:
        vs.append(EXTRA_DECODERS[name](c))
    return vs
