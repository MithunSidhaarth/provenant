"""Token and tool-call efficiency for tools that Provenant executes itself (the provenant-tools server).

Three mechanisms, all deterministic and all AFTER authorization (the policy check runs on every call, cached
or not, so a cache can never outlive a permission change or an expired grant):

* compression  shrinks tool output to what an agent needs: test runs keep the summary and the failure
               blocks; directory listings skip vendored and generated folders and print each folder's
               path once (an indented tree); search matches are grouped under their file; long files keep
               head and tail with a marker. Errors are never compressed away. `full: true` returns everything.
* caching      read-only tools only (read_file, list_directory, search_text). The key includes the tool,
               arguments, session, mode, policy version and a freshness token (size + mtime of every path
               involved), so an edited file or a policy change is a miss. Writes, sends, shell and network
               calls are never cached.
* dedup        when an agent re-reads an unchanged file in the same session, it gets a short reference to its
               earlier result instead of the same bytes again (opt out per call with `full: true`, or for the
               server with --no-dedup).

Token counts in reports are estimates (ceil(characters / 4)) unless a real tokenizer is supplied; bytes and
characters are exact.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path

from .models import canonical_json

_DEF = re.compile(r"^\s*(async\s+def|def|class|function|export\s+(default\s+)?(function|class|const)|interface|type\s+\w+\s*=|"
                  r"struct|enum|impl|fn|func|pub\s+fn|public|private|protected)\b")
CACHEABLE = {"read_file", "list_directory", "search_text"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".mypy_cache", ".pytest_cache",
             ".tox", ".next", "target", ".idea", ".vscode"}


def est_tokens(text: str) -> int:
    return math.ceil(len(text) / 4)


def freshness(paths: list[Path]) -> str:
    parts = []
    for p in paths:
        try:
            st = p.stat()
            parts.append(f"{p}:{st.st_size}:{st.st_mtime_ns}")
            if p.is_dir():                      # a listing changes when a child is added, removed or touched
                for c in sorted(p.iterdir())[:2000]:
                    cs = c.stat()
                    parts.append(f"{c.name}:{cs.st_size}:{cs.st_mtime_ns}")
        except OSError:
            parts.append(f"{p}:missing")
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


@dataclass
class Stats:
    calls: int = 0
    cache_hits: int = 0
    dedup_hits: int = 0
    raw_chars: int = 0
    returned_chars: int = 0

    def to_dict(self) -> dict:
        return {**self.__dict__, "est_tokens_raw": math.ceil(self.raw_chars / 4),
                "est_tokens_returned": math.ceil(self.returned_chars / 4)}


@dataclass
class Efficiency:
    enabled: bool = True
    dedup: bool = True
    max_file_chars: int = 16000
    max_listing_entries: int = 300
    max_matches: int = 60
    _cache: dict = field(default_factory=dict)
    _seen: dict = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    stats: Stats = field(default_factory=Stats)

    def key(self, tool: str, args: dict, session: str, mode: str, policy_version: str, paths: list[Path]) -> str:
        a = {k: v for k, v in args.items() if k != "full"}
        return hashlib.sha256(canonical_json([tool, a, session, mode, policy_version, freshness(paths)]).encode()).hexdigest()

    def lookup(self, tool: str, key: str) -> str | None:
        if not self.enabled or tool not in CACHEABLE:
            return None
        with self._lock:
            return self._cache.get(key)

    def store(self, tool: str, key: str, text: str) -> None:
        if self.enabled and tool in CACHEABLE:
            with self._lock:
                self._cache[key] = text
                if len(self._cache) > 512:
                    self._cache.pop(next(iter(self._cache)))

    def dedupe(self, tool: str, key: str, text: str, call_no: int, full: bool) -> str:
        """Same unchanged result already returned in this session: send a reference instead of the bytes."""
        if not (self.enabled and self.dedup) or full or tool not in CACHEABLE or len(text) < 400:
            return text
        key = key + hashlib.sha256(text.encode()).hexdigest()      # same shaped output, not just the same request
        with self._lock:
            first = self._seen.get(key)
            if first is None:
                self._seen[key] = call_no
                return text
        self.stats.dedup_hits += 1
        digest = hashlib.sha256(text.encode()).hexdigest()[:12]
        return (f"[provenant] unchanged since your call #{first} in this session ({len(text)} chars, sha256 {digest}). "
                f"Call again with \"full\": true if you no longer have it.")

    # --- compression ---------------------------------------------------------------------------
    def file(self, text: str, full: bool) -> str:
        """Long files: an outline of definitions with line numbers plus the opening lines, so the agent can read
        exactly the part it needs with offset/limit instead of paying for the whole file."""
        if not self.enabled or full or len(text) <= self.max_file_chars:
            return text
        lines = text.splitlines()
        outline = [f"{i + 1}: {ln.strip()[:120]}" for i, ln in enumerate(lines) if _DEF.match(ln)][:300]
        head = "\n".join(lines[:40])
        if not outline:
            tail = text[-self.max_file_chars // 3:]
            return (text[: self.max_file_chars * 2 // 3] + f"\n[provenant] … middle omitted ({len(text)} chars total). "
                    "Read a range with offset/limit, or ask with \"full\": true. …\n" + tail)
        return (f"[provenant] {len(lines)} lines ({len(text)} chars); showing an outline and the first 40 lines. Read a range "
                "with offset/limit (0-based line offset), or ask with \"full\": true.\n\nOutline (line: definition):\n"
                + "\n".join(outline) + "\n\nFirst 40 lines:\n" + head)

    def tests(self, out: str, code: int, full: bool) -> str:
        if not self.enabled or full:
            return out
        lines = out.splitlines()
        keep, block = [], False
        for ln in lines:
            if re.match(r"^(FAIL|ERROR):|^=+ (FAILURES|ERRORS|short test summary)|^_{3,} ", ln):
                block = True
            if re.match(r"^Ran \d+ tests? in|^=+ .*\b(passed|failed|error)", ln):
                block = False
                keep.append(ln)
                continue
            if block or re.match(r"^(OK|FAILED)\b", ln):
                keep.append(ln)
        body = "\n".join(keep[-400:]) if keep else "\n".join(lines[-40:])
        status = "passed" if code == 0 else f"FAILED (exit {code})"
        return f"[provenant] tests {status}. Progress lines omitted; failures and summary kept.\n{body}"

    def listing(self, entries: list[str], full: bool) -> list[str]:
        if not self.enabled or full or len(entries) <= self.max_listing_entries:
            return entries
        return entries[: self.max_listing_entries] + [f"[provenant] … {len(entries) - self.max_listing_entries} more entries"]

    def tree(self, entries: list[str], full: bool) -> list[str]:
        """`a/b/c.py  12B` lines → an indented tree, so a deep folder's path is printed once, not on every entry."""
        if not self.enabled or full:
            return entries
        out = []
        for e in entries:
            if e.startswith("[provenant]"):
                out.append(e)
                continue
            name, _, rest = e.partition("  ")
            trail = "/" if name.endswith("/") else ""
            parts = name.rstrip("/").split("/")
            out.append("  " * (len(parts) - 1) + parts[-1] + trail + ("  " + rest if rest else ""))
        return out

    def search(self, lines: list[str], full: bool) -> list[str]:
        """`path:line: text` matches → the path once, then `  line: text` for each match in that file."""
        if not self.enabled or full:
            return lines
        out, last = [], None
        for ln in lines:
            path, sep, rest = ln.partition(":")
            if not sep or ln.startswith("[provenant]"):
                out.append(ln)
                last = None
                continue
            if path != last:
                out.append(path)
                last = path
            out.append("  " + rest)
        return out

    def skip_dir(self, name: str, full: bool) -> bool:
        return self.enabled and not full and name in SKIP_DIRS

    def note(self, raw: str, returned: str) -> None:
        self.stats.calls += 1
        self.stats.raw_chars += len(raw)
        self.stats.returned_chars += len(returned)


def env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.lower() not in ("0", "false", "no", "off")
