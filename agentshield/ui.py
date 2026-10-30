"""Terminal presentation for the `provenant` command: colour, symbols and layout, nothing else.

Colour is used only on a real terminal, never when NO_COLOR is set or output is piped, so logs and
scripts get plain text. Windows 10+ consoles get ANSI enabled; consoles that cannot print the
symbols fall back to ASCII.
"""
from __future__ import annotations

import os
import re
import shutil
import sys

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _enable_windows_vt() -> bool:
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not k.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        return bool(k.SetConsoleMode(h, mode.value | 0x0004))   # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        return False


def _setup() -> tuple[bool, bool]:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    color = tty and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"
    if color and sys.platform == "win32":
        color = _enable_windows_vt()
    enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    fancy = "utf" in enc and not os.environ.get("PROVENANT_ASCII")
    return color, fancy


COLOR, FANCY = _setup()


def _c(code: str):
    return lambda s: f"\x1b[{code}m{s}\x1b[0m" if COLOR else str(s)


bold, dim, red, green, yellow, cyan, magenta = (_c("1"), _c("2"), _c("31"), _c("32"), _c("33"), _c("36"), _c("35"))
on_red, on_green, on_yellow = _c("1;97;41"), _c("1;30;42"), _c("1;30;43")

SYM = {"ok": "✓", "no": "✗", "hold": "⏸", "dot": "·", "arrow": "→", "brand": "◆", "warn": "!", "bar": "│"} if FANCY else \
      {"ok": "+", "no": "x", "hold": "||", "dot": "-", "arrow": "->", "brand": "#", "warn": "!", "bar": "|"}


def width() -> int:
    return max(60, min(110, shutil.get_terminal_size((100, 20)).columns))


def visible_len(s: str) -> int:
    return len(_ANSI.sub("", s))


def clip(s: str, n: int) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: max(1, n - 1)] + ("…" if FANCY else "~")


def banner(version: str, tagline: str = "a firewall between AI agents and their tools") -> str:
    return f"\n  {magenta(SYM['brand'])} {bold('provenant')} {dim(version)}  {dim(SYM['dot'] + ' ' + tagline)}"


def badge(decision: str) -> str:
    return {"ALLOW": on_green("  OK   "), "DENY": on_red(" BLOCK "), "REQUIRE_APPROVAL": on_yellow(" HOLD  ")}.get(
        decision, f" {decision[:5]:<5} ") if COLOR else {"ALLOW": "[ OK  ]", "DENY": "[BLOCK]",
                                                          "REQUIRE_APPROVAL": "[HOLD ]"}.get(decision, f"[{decision[:5]}]")


def row(mark: str, label: str, detail: str = "", label_w: int = 16) -> str:
    pad = " " * max(1, label_w - visible_len(label))
    return f"  {mark} {label}{pad}{detail}"


def good(s: str) -> str:
    return green(SYM["ok"]) + " " + s


def short_path(p) -> str:
    s, home = str(p), os.path.expanduser("~")
    return "~" + s[len(home):] if home not in ("", "~", "/") and s.startswith(home) else s


def section(title: str) -> str:
    return "\n  " + bold(title)
