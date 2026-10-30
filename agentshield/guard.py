"""Provenant Guard: the policy enforcement point for REAL tools.

The rest of the package proves the design inside a simulated world. This module applies the same
design to tools that really run: shell commands, file reads and writes, web fetches and any MCP
server's tools. It is used by two real interception points:

    agentshield.mcp_proxy   sits between any MCP client (Claude Desktop, Cursor, VS Code, Claude Code)
                            and a real MCP server; only ALLOWed tools/call requests are forwarded.
    agentshield.cc_hook     a Claude Code PreToolUse/PostToolUse/UserPromptSubmit hook; DENY blocks the
                            tool, REQUIRE_APPROVAL becomes Claude Code's own "ask the human" prompt.

Same principles as policy.py: deterministic code decides, the model's text is evidence only, the
most restrictive finding wins, and any error, unknown shape or unloadable policy fails closed.

State lives in PROVENANT_HOME (default ~/.provenant): a persistent hash-chained audit log, per-session
taint state, human approvals and the HMAC key. Hooks are short-lived processes, so state is on disk.
"""
from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from .audit import AuditLog
from .detectors import scan_injection, scan_sensitive
from .models import Decision, Finding, PolicyResult, canonical_json, most_restrictive, new_id, sha256_hex
from .netguard import classify_host
from .normalize import canonical, obfuscation_signals, views
from .state import StateDB, StateUnavailable

ALLOW, DENY, APPROVE = Decision.ALLOW, Decision.DENY, Decision.REQUIRE_APPROVAL
DEFAULT_GUARD_POLICY = Path(__file__).resolve().parent / "guard_policy.json"   # built-in; ~/.provenant/policy.json overrides
CATEGORY_ORDER = ("shell", "write", "send", "network", "read")
SIDE_EFFECTS = {"shell", "write", "send", "network", "unknown"}
READ_VERBS = ("read", "get", "list", "search", "find", "view", "describe", "query", "stat", "glob", "grep", "ls")

# --- shell command rules --------------------------------------------------------------------------
# (pattern, decision, reason). Matched case-insensitively against every decoded view of the command.
_ROOTISH = r"(?:/|~|\$home|/\*|~/\*|\.\.?/?\*?|[a-z]:\\?\*?|%userprofile%|\$env:userprofile)"
SHELL_RULES: list[tuple[str, Decision, str]] = [
    (r"\brm\s+(-[a-z]*\s+)*-[a-z]*(r[a-z]*f|f[a-z]*r)[a-z]*\s+(--\s+)?(\"|')?" + _ROOTISH + r"(\"|')?(\s|;|&|\||$)", DENY,
     "recursive force-delete of a root, home or whole-workspace path"),
    (r"--no-preserve-root", DENY, "rm --no-preserve-root"),
    (r"\bfind\s+(/|~/?|\$home|[a-z]:\\)(\s|$)[^|;&]*(-delete\b|-exec\s+(rm|shred)\b)", DENY,
     "find -delete / -exec rm over a root or home path"),
    (r">\s*/dev/(sd|nvme|hd|disk|xvd|mmcblk|vd)", DENY, "overwrites a raw block device via redirection"),
    (r"\bshred\b[^|;&]*(/dev/|\s(/|~/?|\$home)(\s|$))", DENY, "shreds a disk or a root/home path"),
    (r"\bmkfs(\.\w+)?\b|\bdd\s+[^|;&]*\bof=/dev/(sd|nvme|hd|disk|xvd)", DENY, "formats or overwrites a disk"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", DENY, "fork bomb"),
    (r"\b(shutdown|reboot|halt|poweroff)\b|\binit\s+[06]\b", DENY, "shuts down or reboots the machine"),
    (r"\bchmod\s+(-r\s+)?[0-7]*777\s+" + _ROOTISH + r"(\s|$)", DENY, "makes a root or home tree world-writable"),
    (r"\b(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b"
     r"|\b(curl|wget)\b[^|;&]*\|\s*(python3?|perl|ruby|node)\b|\biex\s*\(?\s*(iwr|irm|invoke-webrequest|new-object\s+net\.webclient)",
     DENY, "downloads and executes remote code"),
    (r"\bbase64\s+(-d|--decode)\b[^|;&]*\|\s*(ba|z)?sh\b|\bpowershell(\.exe)?\s+[^|;&]*-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{16,}",
     DENY, "executes an encoded payload"),
    (r"\b(nc|ncat|netcat)\b[^|;&]*\s-[a-z]*e\s|/dev/tcp/|\bsocat\b[^|;&]*exec:", DENY, "opens a reverse shell"),
    (r"\b(curl|wget|http|https)\b[^|;&]*(\s-d\s*@|\s--data(-binary|-raw)?\s*@|\s-f\s+\S+=@|\s-t\s|--upload-file|--post-file)",
     DENY, "uploads a local file to a remote host"),
    (r"\b(format)\s+[a-z]:|\brd\s+/s\s+/q\s+[a-z]:\\?(\s|$)|\bdel\s+(/[a-z]\s+)*[a-z]:\\\*|"
     r"\bremove-item\b[^|;&]*-recurse[^|;&]*\s[a-z]:\\?(\s|$)|\bvssadmin\s+delete\s+shadows|\bbcdedit\b|\bcipher\s+/w",
     DENY, "destructive Windows disk or system command"),
    (r"\breg(\.exe)?\s+delete\s+hk(lm|ey_local_machine)", DENY, "deletes machine-wide registry keys"),
    (r"\bhistory\s+-c\b|\bunset\s+histfile\b|\bshred\b[^|;&]*\.(bash|zsh)_history|\bwevtutil\s+cl\b|\bclear-eventlog\b",
     DENY, "erases shell history or event logs"),
    (r"(agentshield\.(guard|cc_hook|mcp_proxy)|provenant(\.bat)?)\b[^|;&]*\b(approve|reject|disable|reset)\b", DENY,
     "an agent may not approve its own held calls or switch off the guard"),
    (r"\bgit\s+push\b[^|;&]*(\s--force\b|\s-f\b|\s\+)", DENY, "force-push rewrites shared history"),
    (r"(^|[;&|]\s*)(printenv|env|set)\s*(\||>|$)|\bget-childitem\s+env:|\bgci\s+env:", APPROVE,
     "dumps every environment variable (often holds tokens)"),
    (r"\bsudo\b|\bsu\s+-|\brunas\b|\bstart-process\b[^|;&]*-verb\s+runas", APPROVE, "runs with elevated privileges"),
    (r"\brm\s+(-[a-z]*\s+)*-[a-z]*r", APPROVE, "recursive delete"),
    (r"\b(del|erase)\s+/[sq]|\bremove-item\b[^|;&]*-recurse|\brd\s+/s", APPROVE, "recursive delete (Windows)"),
    (r"\bgit\s+(push|reset\s+--hard|clean\s+-[a-z]*f|checkout\s+--\s|branch\s+-d)", APPROVE,
     "git action that publishes or discards work"),
    (r"\b(npm|pnpm|yarn)\s+(publish|unpublish)|\btwine\s+upload|\bcargo\s+publish|\bgh\s+(release|repo\s+delete|pr\s+merge)",
     APPROVE, "publishes to a public registry or repository"),
    (r"\b(pip3?|npm|pnpm|yarn|gem|cargo|go)\s+(install|add|i)\b|\buv\s+(pip\s+install|add)|\bnpx\s+\S", APPROVE,
     "installs third-party code"),
    (r"\b(crontab|schtasks|systemctl\s+(enable|start)|launchctl\s+load|new-scheduledtask)", APPROVE,
     "installs persistence (scheduled task or service)"),
    (r"\b(kill|pkill|killall|taskkill)\b", APPROVE, "kills processes"),
    (r"\bshred\b|\bfind\b[^|;&]*(-delete\b|-exec\s+rm\b)", APPROVE, "deletes files irrecoverably or in bulk"),
    (r"\bdocker\s+(run|exec)\b[^|;&]*(--privileged|-v\s+/:)", DENY, "privileged container or host root mount"),
    (r"\b(ssh|scp|sftp|rsync)\b[^|;&]*@", APPROVE, "connects to a remote machine"),
    (r"\b(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^|;&]*\s-(x\s*(post|put|delete|patch)|d\b|-data\b|f\b)",
     APPROVE, "sends data to a remote host"),
    # --- credential theft beyond dotfiles: reading secret stores or printing tokens (DENY) --------
    (r"\bsecurity\s+(dump-keychain|find-(generic|internet)-password)\b", DENY, "dumps macOS keychain secrets"),
    (r"\bgpg\b[^|;&]*--export-secret-keys\b", DENY, "exports GPG private keys"),
    (r"\bgh\s+auth\s+token\b", DENY, "prints the GitHub auth token"),
    (r"\baws\s+configure\s+get\s+aws_secret_access_key\b", DENY, "prints the AWS secret access key"),
    (r"\b(op|lpass|bw|1password|security)\b[^|;&]*\b(get|read|show|reveal)\b[^|;&]*(password|secret|token|item|note)",
     DENY, "reads a secret out of a password manager"),
    # --- destructive cloud / infrastructure (hold for a human) ------------------------------------
    (r"\b(kubectl|oc)\s+delete\b", APPROVE, "deletes Kubernetes resources"),
    (r"\bhelm\s+(delete|uninstall)\b", APPROVE, "removes a Helm release"),
    (r"\bterraform\s+(destroy|apply\b[^|;&]*-destroy)", APPROVE, "tears down infrastructure"),
    (r"\baws\s+[a-z0-9-]+\s+(delete[a-z-]*|rm|rb|terminate[a-z-]*|purge)\b", APPROVE, "deletes or terminates AWS resources"),
    (r"\b(gcloud|az)\b[^|;&]*\b(delete|destroy)\b", APPROVE, "deletes GCP or Azure resources"),
    (r"\bdocker\b[^|;&]*\b(system\s+prune|volume\s+(rm|prune)|image\s+prune|rmi)\b", APPROVE,
     "removes Docker images, volumes or build data"),
    (r"\bgit\s+filter-branch\b|\bgit\s+reflog\s+expire\b|\bgit-filter-repo\b|\bbfg\b", APPROVE, "rewrites git history"),
    # --- destructive database operations (hold for a human) ---------------------------------------
    (r"(?:^|[;\n]|['\x27\x22\x60]\s*)\s*drop\s+(database|schema|table|collection)\b", APPROVE, "drops a database, schema or table"),
    (r"(?:^|[;\n]|[\x27\x22\x60]\s*)\s*truncate\s+(table\s+)?[\"`\[]?\w", APPROVE, "truncates a table"),
    (r"(?:^|[;\n]|[\x27\x22\x60]\s*)\s*delete\s+from\s+[\"`\[]?\w[\w.\"`\]]*\s*(;|$)", APPROVE, "SQL DELETE with no WHERE clause"),
    (r"(?:^|[;\n]|[\x27\x22\x60]\s*)\s*update\s+[\"`\[]?\w[\w.\"`\]]*\s+set\b(?![^;]*\bwhere\b)", APPROVE, "SQL UPDATE with no WHERE clause"),
    (r"\b(flushall|flushdb)\b", APPROVE, "wipes a datastore (redis FLUSHALL / FLUSHDB)"),
    (r"\.dropdatabase\s*\(|\bdb\.\w+\.drop\s*\(", APPROVE, "drops a MongoDB database or collection"),
    # --- exfiltration over non-HTTP channels (hold for a human) -----------------------------------
    (r"\b(dig|nslookup|host|drill)\b[^|;&]*\$\(", APPROVE, "possible DNS exfiltration via command substitution"),
    (r"\|\s*(nc|ncat|netcat)\s+\S+\s+\d+", APPROVE, "streams data to a raw network socket"),
]
SHELL_RULES_C = [(re.compile(p, re.IGNORECASE | re.MULTILINE), d, r) for p, d, r in SHELL_RULES]

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
    (r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}", "aws_secret_key"),
    (r"gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,}", "github_token"),
    (r"sk-ant-[A-Za-z0-9_\-]{20,}", "anthropic_key"),
    (r"\bsk-(proj-)?[A-Za-z0-9_\-]{32,}", "openai_style_key"),
    (r"xox[abposr]-[A-Za-z0-9\-]{10,}", "slack_token"),
    (r"AIza[0-9A-Za-z_\-]{35}", "google_api_key"),
    (r"(sk|rk)_live_[0-9A-Za-z]{20,}", "stripe_live_key"),
    (r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY", "private_key"),
    (r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "jwt"),
    (r"glpat-[A-Za-z0-9_\-]{20,}", "gitlab_token"),
    (r"hf_[A-Za-z0-9]{34,}", "huggingface_token"),
    (r"npm_[A-Za-z0-9]{36}", "npm_token"),
    (r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}", "sendgrid_key"),
    (r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\s*[=:]\s*['\"]?[^\s'\"]{8,}", "credential_assignment"),
    # Regulated personal identifiers (treated like secrets when leaving in an outbound call).
    (r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", "iban"),
    (r"\b\d{4}\s\d{4}\s\d{4}\b", "aadhaar"),
    (r"\b[A-Z]{5}\d{4}[A-Z]\b", "india_pan"),
]
SECRET_PATTERNS_C = [(re.compile(p), name) for p, name in SECRET_PATTERNS]

URL_RE = re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>`)\]}]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
PATH_KEYS = {"file_path", "path", "paths", "notebook_path", "filename", "file", "source", "destination", "dest",
             "target", "directory", "dir", "src", "dst", "old_path", "new_path"}
COMMAND_KEYS = {"command", "cmd", "script", "shell", "commandline", "command_line", "code"}
WRITE_CONTENT_KEYS = {"content", "new_string", "new_source", "edits", "text", "body", "data"}
_PRIVATE_HOST = re.compile(r"^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.0\.0\.0|\[?::1\]?$|metadata\.google\.internal)")


def redact_secrets(text: str) -> str:
    for rx, name in SECRET_PATTERNS_C:
        text = rx.sub(lambda m, n=name: f"[REDACTED:{n}:{sha256_hex(m.group(0))[:8]}]", text)
    return text


def audit_view(args: Any, detail: str) -> dict:
    """What the audit log keeps about tool arguments. minimal (default): a digest and the argument names only.
    standard: values truncated to 200 characters. full: everything (explicit opt-in). Secrets are always redacted."""
    digest = sha256_hex(canonical_json(args))
    if detail == "full":
        return {"args": args, "args_digest": digest}
    if detail == "standard":
        def cut(v):
            if isinstance(v, str):
                return v[:200] + ("…" if len(v) > 200 else "")
            if isinstance(v, dict):
                return {k: cut(x) for k, x in list(v.items())[:50]}
            if isinstance(v, list):
                return [cut(x) for x in v[:50]]
            return v
        return {"args": cut(args), "args_digest": digest}
    return {"arg_keys": sorted(args)[:50] if isinstance(args, dict) else [], "args_digest": digest}


def scan_secrets(text: str) -> list[dict]:
    hits = [{"type": name, "match": m.group(0)[:6] + "…"} for rx, name in SECRET_PATTERNS_C for m in rx.finditer(text)]
    return hits + [h for h in scan_sensitive(text) if h["type"] != "card_number" or _luhn(h["match"])]


def _luhn(masked: str) -> bool:
    # scan_sensitive masks the card number, so only keep its verdict when the payload had a plausible card.
    return True


def _strings(obj: Any) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _strings(v)]
    if isinstance(obj, (list, tuple)):
        return [s for v in obj for s in _strings(v)]
    return [] if obj is None else [str(obj)]


def flatten_text(obj: Any) -> str:
    """Tool output or MCP content blocks flattened to their text leaves."""
    if isinstance(obj, dict) and isinstance(obj.get("content"), list):
        return "\n".join(flatten_text(c.get("text", c) if isinstance(c, dict) else c) for c in obj["content"])
    return "\n".join(_strings(obj))


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _glob_match(path: str, pattern: str) -> bool:
    p = path.replace("\\", "/").lower()
    pat = pattern.lower()
    if pat.startswith("**/"):
        tail = pat[3:]
        parts = p.split("/")
        return any(fnmatch.fnmatchcase("/".join(parts[i:]), tail) or fnmatch.fnmatchcase("/".join(parts[i:]), tail.rstrip("/*") + "/*")
                   for i in range(len(parts)))
    return fnmatch.fnmatchcase(p, pat)


def match_any(path: str, patterns: list[str]) -> str | None:
    for pat in patterns:
        if _glob_match(path, pat) or (pat.endswith("/**") and _glob_match(path + "/x", pat)):
            return pat
    return None


class SharedAuditLog(AuditLog):
    """The audit chain shared by every hook and proxy process: each append re-reads the chain head from
    disk under the store lock, so concurrent writers extend one chain instead of forking it."""

    def __init__(self, path: Path, key: bytes, store: "Store") -> None:
        super().__init__(path, key=key)
        self._store = store
        self.entries, self._offset = [], 0          # loaded under the lock on first use, never mid-write

    def _scrub(self, obj: Any) -> Any:
        """Recognisable secrets never reach the log, whatever the configured detail level."""
        if isinstance(obj, str):
            return redact_secrets(obj)
        if isinstance(obj, dict):
            return {k: self._scrub(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._scrub(v) for v in obj]
        return obj

    def _reload(self) -> None:
        """Read only what other processes appended since we last looked."""
        if not self.path.exists():
            return
        with self.path.open("rb") as fh:
            fh.seek(self._offset)
            tail = fh.read()
        self.entries += [json.loads(l) for l in tail.decode("utf-8").splitlines() if l.strip()]
        self._offset += len(tail)

    def _note_written(self) -> None:
        self._offset = self.path.stat().st_size

    def append(self, event: str, session_id: str, data: dict) -> dict:
        with self._store.lock():
            self._reload()
            entry = super().append(event, session_id, data)
            self._note_written()
            return entry

    def base(self) -> tuple[int, str]:
        """After retention pruning the chain resumes from a MAC-signed (seq, prev_hash) record. A missing or
        forged record makes verification fail rather than silently restarting from genesis."""
        rp = self.path.parent / "retention.json"
        if not rp.exists():
            return 0, "0" * 64
        try:
            r = json.loads(rp.read_text(encoding="utf-8"))
            body = canonical_json({"first_seq": r["first_seq"], "prev_hash": r["prev_hash"]})
            if not hmac.compare_digest(r["mac"], hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()):
                raise ValueError("bad mac")
            return int(r["first_seq"]), str(r["prev_hash"])
        except Exception:
            return -1, "invalid-retention-record"

    def snapshot(self) -> list[dict]:
        with self._store.lock():
            self._reload()
        return list(self.entries)

    def verify(self, entries: list[dict] | None = None) -> dict:
        if entries is None:
            with self._store.lock():
                self._reload()
        return super().verify(entries)


# --- persistent state -----------------------------------------------------------------------------
def provenant_home() -> Path:
    return Path(os.environ.get("PROVENANT_HOME") or Path.home() / ".provenant")


def runtime_mode() -> str:
    """live unless explicitly demo. The hosted site sets PROVENANT_HOSTED=1, which forces demo."""
    if os.environ.get("PROVENANT_HOSTED") == "1":
        return "demo"
    return "demo" if os.environ.get("PROVENANT_MODE", "live").lower() == "demo" else "live"


class Store:
    """Everything the guard keeps between short-lived processes: the HMAC key, the shared audit chain
    (append-only JSONL under a cross-process lock) and the SQLite authorization state (sessions, approvals,
    grants, checkpoints). Demo and live keep separate databases, and every record also carries its mode."""

    def __init__(self, home: Path | str | None = None, mode: str | None = None) -> None:
        self.home = Path(home) if home else provenant_home()
        self.home.mkdir(parents=True, exist_ok=True)
        self.mode = mode or runtime_mode()
        key_file = self.home / "key"
        env_key = os.environ.get("AGENTSHIELD_AUDIT_KEY")
        if env_key:
            self.key = env_key.encode()
        else:
            try:                        # O_EXCL: two first-run processes cannot end up with different keys
                fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(secrets.token_hex(32))
            except FileExistsError:
                pass
            for _ in range(50):
                k = key_file.read_text(encoding="utf-8").strip()
                if k:
                    break
                time.sleep(0.02)
            self.key = k.encode()
        self._depth = threading.local()
        self.db = StateDB(self.home / ("state.db" if self.mode == "live" else "demo-state.db"))
        self.audit = SharedAuditLog(self.home / "audit.jsonl", key=self.key, store=self)

    @contextlib.contextmanager
    def lock(self, timeout: float = 10.0):
        """Cross-process lock (hooks for parallel tool calls run at the same time). Re-entrant per thread."""
        depth = getattr(self._depth, "n", 0)
        if depth:
            self._depth.n = depth + 1
            try:
                yield
            finally:
                self._depth.n -= 1
            return
        path = self.home / "lock"
        deadline = time.time() + timeout
        while True:
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                break
            except FileExistsError:
                try:
                    if time.time() - path.stat().st_mtime > timeout:     # holder crashed
                        path.unlink()
                        continue
                except OSError:
                    continue
                if time.time() > deadline:
                    raise TimeoutError("could not take the Provenant state lock")
                time.sleep(0.01)
        self._depth.n = 1
        try:
            yield
        finally:
            self._depth.n = 0
            try:
                path.unlink()
            except OSError:
                pass

    def load_session(self, sid: str) -> dict:
        return self.db.load_session(sid, {"session_id": sid, "user_texts": [], "untrusted_texts": [],
                                          "injection_flags": [], "call_count": 0, "mode": self.mode})

    def save_session(self, s: dict) -> None:
        s["untrusted_texts"] = s["untrusted_texts"][-200:]
        s["user_texts"] = s["user_texts"][-50:]
        s["injection_flags"] = s["injection_flags"][-50:]
        self.db.save_session(s["session_id"], self.mode, s)

    def approvals(self) -> dict:
        return {a["approval_id"]: a for a in self.db.list_approvals()}


# --- the engine -----------------------------------------------------------------------------------
@dataclass
class GuardCall:
    tool: Any
    args: Any
    session_id: str
    workspace: str = ""
    source: str = "mcp"               # mcp | claude-code
    call_id: str = field(default_factory=lambda: new_id("call"))

    def fingerprint(self) -> str:
        return sha256_hex(canonical_json({"tool": self.tool, "args": self.args, "session_id": self.session_id}))


class GuardPolicy:
    def __init__(self, config: dict | None, load_error: str | None = None) -> None:
        self.config = config or {}
        self.load_error = load_error
        if config is not None and load_error is None:
            try:
                for k in ("tools", "categories", "network", "paths"):
                    if not isinstance(config[k], dict):
                        raise ValueError(f"{k} must be an object")
                Decision(config["unknown_tool"])
                Decision(config["network"]["unlisted_host"])
                Decision(config["paths"]["outside_workspace_read"])
                Decision(config["paths"]["outside_workspace_write"])
                for v in list(config["tools"].values()) + list(config.get("category_defaults", {}).values()):
                    Decision(v)
                int(config["max_calls_per_session"])
            except Exception as exc:
                self.load_error = f"invalid guard policy: {type(exc).__name__}: {exc}"
        self.version = str(self.config.get("version", "unloaded"))

    @classmethod
    def from_file(cls, path: Path | str | None = None) -> "GuardPolicy":
        user = provenant_home() / "policy.json"
        path = path or os.environ.get("PROVENANT_POLICY") or (user if user.exists() else DEFAULT_GUARD_POLICY)
        try:
            return cls(json.loads(Path(path).read_text(encoding="utf-8")))
        except Exception as exc:
            return cls(None, load_error=f"guard policy could not be loaded: {exc}")

    # ---------------------------------------------------------------------------------------------
    def category(self, tool: str) -> str:
        base = tool.split("__")[-1].lower() if tool.startswith("mcp__") else tool.lower()
        cats = self.config["categories"]
        for cat in ("shell",):
            if any(fnmatch.fnmatchcase(base, p) for p in cats.get(cat, [])):
                return cat
        verb = re.split(r"[_\-.]", base)[0]
        if verb in READ_VERBS:
            return "read"
        for cat in CATEGORY_ORDER[1:]:
            if any(fnmatch.fnmatchcase(base, p) for p in cats.get(cat, [])):
                return cat
        return "unknown"

    def effective_category(self, tool: str, args: Any) -> str:
        """The name says what a tool claims to be; the arguments say what it can do. A tool called get_shell or
        list_and_run that takes a command is a shell, and read_or_write with content is a write."""
        cat = self.category(tool)
        if isinstance(args, dict):
            keys = {k.lower() for k in args}
            if keys & COMMAND_KEYS and any(isinstance(args[k], (str, list)) for k in args if k.lower() in COMMAND_KEYS):
                return "shell"
            if cat in ("read", "unknown", "network") and keys & PATH_KEYS and keys & {"content", "new_string", "edits", "data"}:
                return "write"
        return cat

    def untrusted_output(self, tool: str) -> bool:
        base = tool.split("__")[-1].lower() if tool.startswith("mcp__") else tool.lower()
        return any(fnmatch.fnmatchcase(base, p) for p in self.config.get("untrusted_output_tools", []))

    def evaluate(self, call: GuardCall, session: dict) -> PolicyResult:
        try:
            fp = call.fingerprint()
        except Exception:
            fp = "unhashable"
        if self.load_error:
            return PolicyResult(DENY, [Finding("policy_loaded", DENY, self.load_error)], fp, self.version)
        findings: list[Finding] = []
        try:
            findings += self._structure(call)
            if any(f.decision == DENY for f in findings):
                return PolicyResult(DENY, findings, fp, self.version)
            cat = self.effective_category(call.tool, call.args)
            findings.append(Finding("category", ALLOW, f"{call.tool} classified as '{cat}'", {"category": cat}))
            for rule in (self._tool_rule, self._budget, self._shell, self._paths, self._network, self._dlp,
                         self._provenance, self._injection_context):
                try:
                    findings += rule(call, session, cat)
                except Exception as exc:
                    findings.append(Finding(rule.__name__[1:], DENY,
                                            f"rule error, failing closed: {type(exc).__name__}: {exc}"))
        except Exception as exc:
            findings.append(Finding("guard", DENY, f"evaluation error, failing closed: {type(exc).__name__}"))
        decision = most_restrictive([f.decision for f in findings])
        if decision == ALLOW:
            findings.append(Finding("default", ALLOW, "all guard checks passed"))
        return PolicyResult(decision, findings, fp, self.version)

    # --- rules -----------------------------------------------------------------------------------
    def _structure(self, call: GuardCall) -> list[Finding]:
        if not isinstance(call.tool, str) or not call.tool or len(call.tool) > 200:
            return [Finding("structure", DENY, "tool name is not a short non-empty string")]
        if not isinstance(call.args, dict):
            return [Finding("structure", DENY, "tool arguments are not an object")]
        if len(canonical_json(call.args)) > int(self.config.get("max_arg_bytes", 200000)):
            return [Finding("structure", DENY, "tool arguments exceed the size limit")]
        return [Finding("structure", ALLOW, "well-formed call")]

    def _tool_rule(self, call, session, cat) -> list[Finding]:
        for pat, dec in self.config["tools"].items():
            if fnmatch.fnmatchcase(call.tool, pat):
                return [Finding("tool_rule", Decision(dec), f"policy sets {call.tool} to {dec}", {"pattern": pat})]
        default = self.config.get("category_defaults", {}).get(cat)
        if default:
            return [Finding("category_default", Decision(default), f"'{cat}' tools default to {default}")]
        if cat == "unknown":
            dec = Decision(self.config["unknown_tool"])
            return [Finding("unknown_tool", dec, f"{call.tool} is not classified by the policy; unclassified tools get {dec.value}")]
        return []

    def _budget(self, call, session, cat) -> list[Finding]:
        limit = int(self.config["max_calls_per_session"])
        if session.get("call_count", 0) >= limit:
            return [Finding("budget", DENY, f"session exceeded its budget of {limit} tool calls")]
        return []

    def _commands(self, call, cat) -> list[str]:
        if cat != "shell":
            return []
        a = call.args
        cmd = a.get("command", a.get("cmd", a.get("script")))
        if isinstance(cmd, list):
            cmd = " ".join(map(str, cmd))
        if not isinstance(cmd, str):
            cmd = " ".join(_strings(a))
        extra = a.get("args")
        if isinstance(extra, list):
            cmd += " " + " ".join(map(str, extra))
        return views(cmd)

    def _shell(self, call, session, cat) -> list[Finding]:
        out, seen = [], set()
        for v in self._commands(call, cat):
            if "rootdel" not in seen and _root_delete(v):
                seen.add("rootdel")
                out.append(Finding("shell", DENY, "command: recursive delete of a root, home or whole-filesystem path"))
            for rx, dec, reason in SHELL_RULES_C:
                if reason not in seen and rx.search(v):
                    seen.add(reason)
                    out.append(Finding("shell", dec, f"command {reason}", {"match": rx.search(v).group(0)[:80]}))
            for tok in _shell_tokens(v):
                pat = match_any(tok, self.config["paths"]["secret_patterns"])
                if pat and f"secret:{tok}" not in seen:
                    seen.add(f"secret:{tok}")
                    out.append(Finding("shell", DENY, f"command touches a credential file ({tok})", {"pattern": pat}))
                pat = match_any(tok, self.config["paths"]["protected_patterns"])
                if pat and f"prot:{tok}" not in seen:
                    seen.add(f"prot:{tok}")
                    out.append(Finding("shell", DENY, f"command touches Provenant's own policy, state or hook config ({tok})",
                                       {"pattern": pat}))
        return out

    def _path_args(self, call) -> list[str]:
        out = []
        for k, v in call.args.items():
            if k.lower() in PATH_KEYS:
                out += [s for s in _strings(v) if s]
        return out

    def _paths(self, call, session, cat) -> list[Finding]:
        pcfg = self.config["paths"]
        out = []
        writing = cat in ("write",)
        for raw in self._path_args(call):
            resolved = _resolve(raw, call.workspace)
            pat = match_any(resolved, pcfg["secret_patterns"]) or match_any(raw, pcfg["secret_patterns"])
            if pat:
                out.append(Finding("paths", DENY, f"{raw} is a credential or secret file", {"pattern": pat}))
                continue
            pat = match_any(resolved, pcfg["protected_patterns"])
            if pat and (writing or cat in ("shell", "unknown")):
                out.append(Finding("paths", DENY, f"{raw} is Provenant's own policy, state or hook config; agents may not change it",
                                   {"pattern": pat}))
                continue
            if writing and match_any(resolved, pcfg["review_write_patterns"]):
                out.append(Finding("paths", APPROVE, f"writing {raw} changes CI, startup or access config"))
            if call.workspace and not _inside(resolved, call.workspace):
                dec = Decision(pcfg["outside_workspace_write" if writing else "outside_workspace_read"])
                out.append(Finding("paths", dec, f"{raw} is outside the workspace {call.workspace}",
                                   {"resolved": resolved}))
        return out

    def _urls(self, call, cat) -> list[str]:
        texts = self._commands(call, cat) if cat == "shell" else _strings(call.args)
        urls = [m.group(0) for t in texts for m in URL_RE.finditer(t)]
        for k in ("url", "uri", "href", "endpoint"):
            v = call.args.get(k)
            if isinstance(v, str) and v and v not in urls:
                urls.append(v if "://" in v else "https://" + v)
        return urls

    def _network(self, call, session, cat) -> list[Finding]:
        ncfg = self.config["network"]
        out = []
        if cat == "write":   # URLs inside file content are text, not requests
            return out
        for u in self._urls(call, cat):
            host = host_of(u)
            if not host:
                out.append(Finding("network", DENY, f"URL '{u[:80]}' has no parsable host"))
            elif (hc := classify_host(host)).restricted or _PRIVATE_HOST.match(host):
                out.append(Finding("network", DENY, f"{host} is a local, private or raw-IP address (SSRF / metadata risk)",
                                   {"host": host, "detail": hc.restricted, "ip": hc.ip}))
            elif not any(fnmatch.fnmatchcase(host, p) or host == p.lstrip("*.") for p in ncfg["allowed_hosts"]):
                dec = Decision(ncfg["unlisted_host"])
                out.append(Finding("network", dec, f"{host} is not on the allowed host list", {"host": host}))
        return out

    def _dlp(self, call, session, cat) -> list[Finding]:
        leaves = _strings(call.args)
        blob = "\n".join(leaves)
        # Reassemble secrets split across arguments: the full concatenation, plus each suffix so a
        # secret whose first fragment follows an unrelated field (e.g. channel="x", a="123-45",
        # b="-6789") still lines up on a word boundary.
        concats = ["".join(leaves)]
        if 1 < len(leaves) <= 24:
            concats += ["".join(leaves[i:]) for i in range(1, len(leaves))]
        hits = []
        for v in views(blob) + concats:
            hits += [h for h in scan_secrets(v) if h not in hits]
        if not hits:
            return []
        if cat in ("shell", "send", "network", "unknown"):
            return [Finding("dlp", DENY, "outbound arguments contain a credential or regulated data", {"matches": hits[:5]})]
        if cat == "write":
            return [Finding("dlp", APPROVE, "file content contains a credential; a human should confirm",
                            {"matches": hits[:5]})]
        return []

    def _provenance(self, call, session, cat) -> list[Finding]:
        """Destinations (hosts, email recipients) must come from the user, not from content the agent read."""
        if cat not in SIDE_EFFECTS - {"write"}:
            return []
        untrusted = [t.lower() for t in session.get("untrusted_texts", [])]
        if not untrusted:
            return []
        user = "\n".join(session.get("user_texts", [])).lower()
        allowed = self.config["network"]["allowed_hosts"]
        targets = {host_of(u) for u in self._urls(call, cat)} - {""}
        blob = "\n".join(self._commands(call, cat) if cat == "shell" else _strings(call.args))
        targets |= {e.lower() for e in EMAIL_RE.findall(blob)}
        tainted = []
        for t in sorted(targets):
            if t in user or any(fnmatch.fnmatchcase(t, p) for p in allowed):
                continue
            if any(t in u for u in untrusted):
                tainted.append(t)
        if tainted:
            return [Finding("provenance", DENY,
                            f"destination(s) {tainted} came from content the agent read, not from the user",
                            {"tainted": tainted})]
        return []

    def _injection_context(self, call, session, cat) -> list[Finding]:
        if cat in SIDE_EFFECTS and session.get("injection_flags"):
            return [Finding("injection_context", APPROVE,
                            "this session has read content containing prompt-injection indicators; side effects need a human",
                            {"indicators": session["injection_flags"][:3]})]
        return []


_ROOT_TARGET = re.compile(r"^(/|/\*|~|~/|~/\*|\$home/?\*?|\$\{home\}/?\*?|\.|\./|\./\*|\*|\.\*|[a-z]:\\?\*?|[a-z]:/\*?|"
                          r"%userprofile%\\?\*?|\$env:userprofile\\?\*?|/(home|users|etc|usr|var|boot|root)/?\*?)$", re.IGNORECASE)
_DELETERS = {"rm", "ri", "remove-item", "del", "erase", "rd", "rmdir"}


def _root_delete(cmd: str) -> bool:
    """rm/Remove-Item and aliases with any spelling of a recursive flag aimed at a root, home or wildcard path."""
    for seg in re.split(r"[;&|\n]+", cmd):
        try:
            toks = shlex.split(seg, posix=True)
        except ValueError:
            toks = seg.split()
        if not toks:
            continue
        i = 0
        while i < len(toks) and toks[i].lower() in ("sudo", "doas", "command", "builtin", "nohup", "time", "xargs", "exec"):
            i += 1
        if i >= len(toks) or PurePosixPath(toks[i].lower().replace("\\", "/")).name.removesuffix(".exe") not in _DELETERS:
            continue
        flags = [t.lower() for t in toks[i + 1:] if t.startswith("-") or t.startswith("/")]
        targets = [t for t in toks[i + 1:] if not t.startswith("-") or t in ("-",)]
        recursive = any(f in ("--recursive", "-recurse", "/s") or f.startswith("--recursive") or f.startswith("-rec")
                        or (re.fullmatch(r"-[a-z]+", f) and "r" in f) for f in flags)
        if recursive and any(_ROOT_TARGET.match(t.rstrip("/") or "/") or _ROOT_TARGET.match(t) for t in targets if t != "--"):
            return True
    return False


def _shell_tokens(cmd: str) -> list[str]:
    toks = cmd.split()                  # keeps Windows backslashes, which posix shlex would eat
    try:
        toks += shlex.split(cmd, posix=True)
    except ValueError:
        pass
    out = []
    for t in toks:
        for part in re.split(r"[;&|<>()]+|^\w+=", t):
            part = part.strip("'\"")
            if part and ("/" in part or "\\" in part or part.startswith(".") or "." in part):
                out.append(part)
    return out


def _resolve(raw: str, workspace: str) -> str:
    p = os.path.expanduser(raw.strip())
    win = bool(re.match(r"^[a-zA-Z]:[\\/]", p)) or bool(re.match(r"^[a-zA-Z]:[\\/]", workspace or ""))
    if win:
        p = p.replace("\\", "/")
        ws = (workspace or "").replace("\\", "/")
        if not re.match(r"^[a-zA-Z]:/", p) and not p.startswith("/"):
            p = ws.rstrip("/") + "/" + p
        parts: list[str] = []
        for seg in p.split("/"):
            if seg == "..":
                if len(parts) > 1:
                    parts.pop()
            elif seg not in ("", "."):
                parts.append(seg)
        return "/".join(parts).lower()
    if not os.path.isabs(p) and workspace:
        p = os.path.join(workspace, p)
    return os.path.normpath(p)


def _inside(resolved: str, workspace: str) -> bool:
    ws = _resolve(workspace, workspace)
    r, w = resolved.replace("\\", "/").rstrip("/").lower(), ws.replace("\\", "/").rstrip("/").lower()
    return r == w or r.startswith(w + "/")


# --- the guard: engine + state + approvals + audit ------------------------------------------------
@dataclass
class Verdict:
    decision: Decision
    reasons: list[str]
    findings: list[dict]
    call_id: str
    approval_id: str | None = None
    approved_by: str | None = None
    grant_id: str | None = None          # ALLOW only: single-use, bound to this call's fingerprint and mode
    fingerprint: str | None = None

    def message(self) -> str:
        if self.decision == ALLOW:
            return "ALLOW" + (f" (approved by {self.approved_by}, {self.approval_id})" if self.approved_by else "")
        if self.decision == APPROVE:
            return (f"REQUIRE_APPROVAL: Provenant is holding this call as {self.approval_id}. Nothing has run. "
                    f"Reasons: {'; '.join(self.reasons)}. A human can approve it with "
                    f"`provenant approve {self.approval_id}` (or by phone with `provenant call {self.approval_id}`), "
                    f"then the identical call may be retried once.")
        return "DENY: Provenant blocked this call. " + "; ".join(self.reasons)


def _locked(fn):
    def wrapper(self, *a, **kw):
        with self.store.lock():
            return fn(self, *a, **kw)
    wrapper.__name__, wrapper.__doc__ = fn.__name__, fn.__doc__
    return wrapper


HUMAN_CHANNELS = ("cli", "phone", "dashboard")


class Guard:
    def __init__(self, policy: GuardPolicy | None = None, store: Store | None = None, clock=time.time) -> None:
        self.policy = policy or GuardPolicy.from_file()
        self.store = store or Store()
        self.clock = clock

    @property
    def audit(self) -> AuditLog:
        return self.store.audit

    @property
    def mode(self) -> str:
        return self.store.mode

    @property
    def detail(self) -> str:
        d = os.environ.get("PROVENANT_AUDIT_DETAIL") or self.policy.config.get("audit_detail", "minimal")
        return d if d in ("minimal", "standard", "full") else "minimal"

    @_locked
    def note_user_text(self, sid: str, text: str, source: str) -> None:
        s = self.store.load_session(sid)
        s["user_texts"].append(text[:4000])
        self.store.save_session(s)
        self.audit.append("user_prompt", sid, {"source": source, "chars": len(text), "mode": self.mode})

    @_locked
    def check(self, call: GuardCall, hold: bool = True, grant: bool = True) -> Verdict:
        """Decide one call. With hold=True a REQUIRE_APPROVAL is stored for a human (and an earlier human
        approval of this exact call is consumed). With hold=False the caller has its own human prompt.
        An ALLOW carries a single-use grant; executors redeem it immediately before running the call."""
        session = self.store.load_session(call.session_id)
        self.audit.append("tool_request", call.session_id, {"call_id": call.call_id, "tool": call.tool,
                                                            "source": call.source, "mode": self.mode,
                                                            **audit_view(call.args, self.detail)})
        try:
            result = self.policy.evaluate(call, session)
            if not isinstance(result.decision, Decision):
                raise TypeError("unsupported decision")
            from .classifier import apply as model_assist   # optional, off by default; can only escalate ALLOW
            result = model_assist(self, call, result)
        except Exception as exc:
            result = PolicyResult(DENY, [Finding("guard", DENY, f"policy evaluation failed ({type(exc).__name__}); failing closed")],
                                  "unhashable", self.policy.version)
        session["call_count"] = session.get("call_count", 0) + 1
        self.store.save_session(session)
        self.audit.append("policy_decision", call.session_id, {"call_id": call.call_id, "tool": call.tool,
                                                               "source": call.source, "mode": self.mode, **_audit_result(result)})
        v = Verdict(result.decision, result.reasons, result.to_dict()["findings"], call.call_id,
                    fingerprint=result.call_fingerprint)
        if result.decision == APPROVE and hold:
            granted = self.store.db.consume_approval(result.call_fingerprint, self.mode, self.clock(), call.call_id)
            if granted:
                self.audit.append("approval_used", call.session_id, {"approval_id": granted["approval_id"],
                                                                     "call_id": call.call_id, "mode": self.mode,
                                                                     "fingerprint": result.call_fingerprint})
                v.decision, v.approval_id, v.approved_by = ALLOW, granted["approval_id"], granted["decided_by"]
            else:
                v.approval_id = self._hold(call, result)
        if grant and v.decision == ALLOW and result.call_fingerprint != "unhashable":
            v.grant_id = new_id("grant")
            self.store.db.issue_grant(v.grant_id, result.call_fingerprint, self.mode, call.session_id, self.clock(),
                                      float(self.policy.config.get("grant_ttl_seconds", 60)))
        return v

    def redeem(self, verdict: Verdict, call: GuardCall) -> bool:
        """The executor's last check: the grant must exist, be unused, unexpired, in this mode, and match
        this exact call. Anything else (including a state error) means the call does not run."""
        try:
            if verdict.decision != ALLOW or not verdict.grant_id or call.fingerprint() != verdict.fingerprint:
                return False
            ok = self.store.db.redeem_grant(verdict.grant_id, verdict.fingerprint, self.mode, self.clock())
        except Exception:
            ok = False
        try:
            self.audit.append("grant_redeemed" if ok else "grant_refused", call.session_id,
                              {"call_id": call.call_id, "grant_id": verdict.grant_id, "mode": self.mode})
        except Exception:
            return False
        return ok

    def _hold(self, call: GuardCall, result: PolicyResult) -> str:
        now = self.clock()
        existing = self.store.db.find_pending(result.call_fingerprint, self.mode, now)
        if existing:                 # the same call asked twice is one request, not a queue flood
            return existing
        aid = new_id("appr")
        self.store.db.create_approval({"approval_id": aid, "fingerprint": result.call_fingerprint, "mode": self.mode,
                                       "tool": call.tool, "args": call.args, "session_id": call.session_id,
                                       "source": call.source, "reasons": result.reasons, "created_at": now,
                                       "expires_at": now + float(self.policy.config.get("approval_ttl_seconds", 900))})
        self.audit.append("approval_requested", call.session_id, {"approval_id": aid, "tool": call.tool,
                                                                  "mode": self.mode, "fingerprint": result.call_fingerprint})
        return aid

    @_locked
    def decide(self, approval_id: str, approver: str, approve: bool, channel: str = "cli",
               evidence: dict | None = None) -> dict:
        if not approver.startswith("human:") or len(approver) < 7:
            return {"ok": False, "reason": "approvals must name a human approver (human:<name>)"}
        if channel not in HUMAN_CHANNELS:
            return {"ok": False, "reason": f"approvals are not accepted over channel '{channel}'"}
        r = self.store.db.decide(approval_id, approve, approver, self.clock(), channel, evidence)
        if r["ok"]:
            p = self.store.db.get_approval(approval_id)
            self.audit.append("approval_granted" if approve else "approval_rejected", p["session_id"],
                              {"approval_id": approval_id, "approver": approver, "channel": channel,
                               "mode": self.mode, "fingerprint": p["fingerprint"], **({"evidence": evidence} if evidence else {})})
        return r

    def get_approval(self, approval_id: str) -> dict | None:
        return self.store.db.get_approval(approval_id)

    def pending(self) -> list[dict]:
        now = self.clock()
        return [p for p in self.store.db.list_approvals("pending") if p["expires_at"] > now and p["mode"] == self.mode]

    @_locked
    def ingest_output(self, sid: str, tool: str, output: Any) -> list[dict]:
        """Record tool output the agent has seen. Untrusted output taints later destinations; injection
        indicators in it make later side effects need a human."""
        if not self.policy.untrusted_output(tool) and not tool.startswith("mcp__"):
            return []
        text = flatten_text(output)[:200000]
        vs = views(text)
        flags, seen = [], set()
        for f in obfuscation_signals(text, scan_injection) + [f for v in vs for f in scan_injection(canonical(v))]:
            if f["label"] not in seen:
                seen.add(f["label"])
                flags.append({**f, "source": tool})
        s = self.store.load_session(sid)
        s["untrusted_texts"] += [v[:20000] for v in vs]
        s["injection_flags"] += flags
        self.store.save_session(s)
        self.audit.append("tool_result", sid, {"tool": tool, "trust": "untrusted", "chars": len(text),
                                               "mode": self.mode, "injection_indicators": flags})
        return flags


def _audit_result(result: PolicyResult) -> dict:
    d = result.to_dict()
    for f in d["findings"]:          # evidence may quote argument values; keep only the rule and reason
        f.pop("evidence", None)
    return d


# --- CLI: approvals and audit for the human ---------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    import argparse
    import getpass
    ap = argparse.ArgumentParser(prog="python -m agentshield.guard",
                                 description="Provenant Guard: human approvals, audit log and dry-run checks for real tools.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("pending", help="list calls held for approval")
    for name in ("approve", "reject"):
        p = sub.add_parser(name, help=f"{name} a held call")
        p.add_argument("approval_id")
        p.add_argument("--as", dest="who", default=None, help="approver name (default: your OS user)")
    lg = sub.add_parser("log", help="show recent audit entries")
    lg.add_argument("-n", type=int, default=20)
    sub.add_parser("verify", help="verify the audit hash chain")
    ck = sub.add_parser("check", help="dry-run a tool call through the policy (nothing runs)")
    ck.add_argument("tool")
    ck.add_argument("args_json", nargs="?", default="{}")
    ck.add_argument("--workspace", default=os.getcwd())
    ns = ap.parse_args(argv)
    g = Guard()
    if ns.cmd == "pending":
        rows = g.pending()
        for p in rows:
            print(f"{p['approval_id']}  {p['tool']}  {json.dumps(p['args'], ensure_ascii=False)[:120]}")
            for r in p["reasons"]:
                print(f"    - {r}")
        if not rows:
            print("nothing is waiting for approval")
        return 0
    if ns.cmd in ("approve", "reject"):
        if not os.isatty(0):        # an agent's shell tool has no terminal; a person typing does
            print("refused: approvals must be typed by a human at a terminal", flush=True)
            return 2
        who = "human:" + (ns.who or getpass.getuser())
        r = g.decide(ns.approval_id, who, ns.cmd == "approve")
        print(json.dumps(r))
        return 0 if r["ok"] else 1
    if ns.cmd == "log":
        for e in g.audit.snapshot()[-ns.n:]:
            d = e["data"]
            extra = d.get("decision", "") + " " + str(d.get("tool", "")) if isinstance(d, dict) else ""
            print(f"{e['seq']:>5} {e['ts']} {e['event']:<20} {extra.strip()}")
        return 0
    if ns.cmd == "verify":
        r = g.audit.verify()
        print(json.dumps(r))
        return 0 if r["ok"] else 1
    if ns.cmd == "check":
        try:
            args = json.loads(ns.args_json)
        except ValueError:
            print("args_json is not valid JSON")
            return 2
        res = g.policy.evaluate(GuardCall(ns.tool, args, "cli-check", ns.workspace, "cli"),
                                g.store.load_session("cli-check"))
        print(res.decision.value)
        for f in res.findings:
            if f.decision != ALLOW:
                print(f"  {f.decision.value:<16} {f.rule}: {f.reason}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
