"""Central policy enforcement point.

Every tool invocation is evaluated here by ordinary, deterministic code. The model's text,
the agent's rationale and anything found in retrieved content are inputs to be judged, never
sources of authority.

Combination rule: each rule emits findings; the most restrictive finding wins
(DENY > REQUIRE_APPROVAL > ALLOW). Any exception, malformed input, unknown tool, unknown agent
or unloadable policy yields DENY.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .detectors import scan_sensitive
from .models import Decision, Finding, PolicyResult, ToolCall, most_restrictive
from .tools import ToolSpec, TOOLS, is_internal_email, is_sim_url

DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "policy" / "policy.json"

ALLOW, DENY, APPROVE = Decision.ALLOW, Decision.DENY, Decision.REQUIRE_APPROVAL


@dataclass
class SessionContext:
    """What the enforcement point knows about the session, maintained by the gateway."""

    session_id: str
    agent_id: str
    user_task: str                                  # trusted: typed by the user
    untrusted_texts: list[str] = field(default_factory=list)   # tool outputs, documents, pages
    injection_flags: list[dict] = field(default_factory=list)
    call_count: int = 0
    known_secrets: dict[str, str] = field(default_factory=dict)  # for DLP matching only


class PolicyError(Exception):
    pass


class PolicyEngine:
    # Rules that run once the call is known to be well formed, in evaluation order.
    RULES = ("permission", "budget", "boundary", "data_classification", "provenance", "dlp",
             "injection_context", "refund_limit", "high_impact")

    def __init__(self, config: dict | None, tools: dict[str, ToolSpec] | None = None,
                 load_error: str | None = None, disabled_rules: tuple[str, ...] = ()) -> None:
        # disabled_rules exists only for the defense-in-depth ablation tests.
        self.disabled_rules = set(disabled_rules)
        self.tools = tools or TOOLS
        self.load_error = load_error
        self.config = config or {}
        if config is not None and load_error is None:
            try:
                self._validate_config(config)
            except Exception as exc:  # malformed policy -> fail closed for every call
                self.load_error = f"invalid policy: {exc}"
        self.version = str(self.config.get("version", "unloaded"))

    @classmethod
    def from_file(cls, path: Path | str = DEFAULT_POLICY_PATH, **kw) -> "PolicyEngine":
        try:
            config = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as exc:
            return cls(None, load_error=f"policy could not be loaded: {exc}", **kw)
        return cls(config, **kw)

    @staticmethod
    def _validate_config(c: dict) -> None:
        if not isinstance(c.get("agents"), dict) or not c["agents"]:
            raise PolicyError("no agents defined")
        for name, prof in c["agents"].items():
            if not isinstance(prof.get("permissions"), list):
                raise PolicyError(f"agent {name} has no permission list")
            if not isinstance(prof.get("max_calls_per_session"), int):
                raise PolicyError(f"agent {name} has no call budget")
        if not isinstance(c.get("refund_limit"), (int, float)):
            raise PolicyError("refund_limit missing")
        cf = c.get("customer_fields", {})
        if not isinstance(cf.get("public"), list) or not isinstance(cf.get("sensitive"), list):
            raise PolicyError("customer_fields missing")
        for k in ("side_effect_tools", "read_only_tools"):
            Decision(c["untrusted_control_args"][k])

    # ---------------------------------------------------------------------------------
    def evaluate(self, call: ToolCall, ctx: SessionContext) -> PolicyResult:
        try:
            fingerprint = call.fingerprint()
        except Exception:
            fingerprint = "unhashable"
        if self.load_error:
            return PolicyResult(DENY, [Finding("policy_loaded", DENY, self.load_error)], fingerprint, self.version)

        findings: list[Finding] = []
        # Structural rules gate the rest: later rules assume a well-formed call.
        for rule in (self._r_structure, self._r_known_tool, self._r_schema):
            try:
                out = rule(call, ctx)
            except Exception as exc:
                out = [Finding(rule.__name__[3:], DENY, f"rule error, failing closed: {type(exc).__name__}")]
            findings.extend(out)
            if any(f.decision == DENY for f in out):
                return PolicyResult(DENY, findings, fingerprint, self.version)

        spec = self.tools[call.tool]
        rules: list[Callable[[ToolCall, SessionContext, ToolSpec], list[Finding]]] = [
            getattr(self, f"_r_{name}") for name in self.RULES if name not in self.disabled_rules]
        for rule in rules:
            try:
                findings.extend(rule(call, ctx, spec))
            except Exception as exc:
                findings.append(Finding(rule.__name__[3:], DENY,
                                        f"rule error, failing closed: {type(exc).__name__}: {exc}"))

        decision = most_restrictive([f.decision for f in findings])
        if decision == ALLOW:
            findings.append(Finding("default", ALLOW, "all policy checks passed"))
        return PolicyResult(decision, findings, fingerprint, self.version)

    # --- structural ---------------------------------------------------------------------
    def _r_structure(self, call: ToolCall, ctx: SessionContext) -> list[Finding]:
        problems = []
        if not isinstance(call.tool, str) or not call.tool:
            problems.append("tool name is not a non-empty string")
        if not isinstance(call.args, dict):
            problems.append("arguments are not an object")
        if call.session_id != ctx.session_id:
            problems.append("call session does not match the enforcing session")
        if call.agent_id != ctx.agent_id:
            problems.append("call agent does not match the session agent")
        if problems:
            return [Finding("structure", DENY, "malformed tool call: " + "; ".join(problems))]
        return [Finding("structure", ALLOW, "well-formed call")]

    def _r_known_tool(self, call: ToolCall, ctx: SessionContext) -> list[Finding]:
        if call.tool not in self.tools:
            return [Finding("known_tool", DENY, f"tool '{call.tool}' is not registered; unsupported tools are denied",
                            {"registered_tools": sorted(self.tools)})]
        return [Finding("known_tool", ALLOW, "registered tool")]

    def _r_schema(self, call: ToolCall, ctx: SessionContext) -> list[Finding]:
        spec = self.tools[call.tool]
        errs = []
        extra = set(call.args) - set(spec.args)
        if extra:
            errs.append(f"unexpected arguments {sorted(extra)}")
        for name, a in spec.args.items():
            if name not in call.args:
                if a.required:
                    errs.append(f"missing argument '{name}'")
                continue
            v = call.args[name]
            if a.type == "string":
                if not isinstance(v, str):
                    errs.append(f"'{name}' must be a string")
                elif len(v) > a.max_len:
                    errs.append(f"'{name}' exceeds {a.max_len} characters")
            elif a.type == "number":
                if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
                    errs.append(f"'{name}' must be a finite number")
            elif a.type == "string_list":
                if not isinstance(v, list) or not v or not all(isinstance(x, str) for x in v):
                    errs.append(f"'{name}' must be a non-empty list of strings")
            else:
                errs.append(f"'{name}' has unsupported type '{a.type}'")
        if errs:
            return [Finding("schema", DENY, "arguments failed validation: " + "; ".join(errs))]
        return [Finding("schema", ALLOW, "arguments match the tool schema")]

    # --- authorization ------------------------------------------------------------------
    def _r_permission(self, call, ctx, spec) -> list[Finding]:
        profile = self.config["agents"].get(call.agent_id)
        if profile is None:
            return [Finding("permission", DENY, f"unknown agent '{call.agent_id}'")]
        if spec.permission not in profile["permissions"]:
            return [Finding("permission", DENY,
                            f"agent '{call.agent_id}' lacks permission '{spec.permission}' required by {spec.name}",
                            {"required": spec.permission, "granted": profile["permissions"]})]
        return [Finding("permission", ALLOW, f"permission '{spec.permission}' granted")]

    def _r_budget(self, call, ctx, spec) -> list[Finding]:
        limit = self.config["agents"][call.agent_id]["max_calls_per_session"]
        if ctx.call_count >= limit:
            return [Finding("budget", DENY, f"session exceeded its budget of {limit} tool calls")]
        return []

    def _r_boundary(self, call, ctx, spec) -> list[Finding]:
        a = call.args
        if spec.name == "send_email" and not is_internal_email(a["to"]):
            return [Finding("boundary", DENY,
                            f"recipient '{a['to']}' is outside the simulated environment (only @corp.example)",
                            {"recipient": a["to"]})]
        if spec.name == "fetch_url" and not is_sim_url(a["url"]):
            return [Finding("boundary", DENY, f"URL '{a['url']}' is outside the simulation (only sim:// is reachable)",
                            {"url": a["url"]})]
        if spec.name == "read_document" and not re.fullmatch(r"[a-z0-9_\-]+", a["doc_id"]):
            return [Finding("boundary", DENY, "document id contains path characters", {"doc_id": a["doc_id"]})]
        return []

    def _r_data_classification(self, call, ctx, spec) -> list[Finding]:
        if spec.name != "lookup_customer":
            return []
        cf = self.config["customer_fields"]
        fields = call.args["fields"]
        sensitive = [f for f in fields if f in cf["sensitive"]]
        unknown = [f for f in fields if f not in cf["sensitive"] and f not in cf["public"]]
        out = []
        if sensitive:
            out.append(Finding("data_classification", DENY,
                               f"requested restricted fields {sensitive}; the agent may not read regulated data",
                               {"restricted_fields": sensitive}))
        if unknown:
            out.append(Finding("data_classification", DENY,
                               f"fields {unknown} are unclassified; unclassified data is denied",
                               {"unclassified_fields": unknown}))
        return out

    def _r_provenance(self, call, ctx, spec) -> list[Finding]:
        """Control arguments must come from the user, not from untrusted content.

        A value is 'tainted' when it appears in untrusted content the session has seen and
        does not appear in the user's own request. This catches injected recipients, URLs,
        amounts and record ids without needing to recognise the injection's wording.
        """
        tainted = {}
        user = ctx.user_task.lower()
        for name, a in spec.args.items():
            if not a.control or name not in call.args:
                continue
            for form in _value_forms(call.args[name]):
                if len(form) < 2 or form in user:
                    continue
                for i, text in enumerate(ctx.untrusted_texts):
                    if form in text.lower():
                        tainted[name] = {"value": call.args[name], "seen_in_untrusted_source": i}
                        break
                if name in tainted:
                    break
                # A value present in neither place was invented; that is acceptable only for reads.
        if not tainted:
            return []
        key = "side_effect_tools" if spec.side_effect else "read_only_tools"
        decision = Decision(self.config["untrusted_control_args"][key])
        return [Finding("provenance", decision,
                        f"control argument(s) {sorted(tainted)} originate from untrusted content, not from the user",
                        {"tainted_args": tainted})]

    def _r_dlp(self, call, ctx, spec) -> list[Finding]:
        if not spec.side_effect:
            return []
        blob = json.dumps(call.args, ensure_ascii=False)
        hits = scan_sensitive(blob, ctx.known_secrets)
        if hits:
            return [Finding("dlp", DENY, "outbound payload contains secrets or regulated data", {"matches": hits})]
        return []

    def _r_injection_context(self, call, ctx, spec) -> list[Finding]:
        if spec.side_effect and ctx.injection_flags:
            return [Finding("injection_context", APPROVE,
                            "session has ingested content with prompt-injection indicators; side effects need a human",
                            {"indicators": ctx.injection_flags[:5]})]
        return []

    def _r_refund_limit(self, call, ctx, spec) -> list[Finding]:
        if spec.name != "issue_refund":
            return []
        amt, limit = call.args["amount"], self.config["refund_limit"]
        if amt <= 0:
            return [Finding("refund_limit", DENY, "refund amount must be positive")]
        if amt > limit:
            return [Finding("refund_limit", DENY, f"refund {amt} exceeds the hard limit of {limit}",
                            {"amount": amt, "limit": limit})]
        return []

    def _r_high_impact(self, call, ctx, spec) -> list[Finding]:
        if spec.high_impact:
            return [Finding("high_impact", APPROVE, f"{spec.name} is a high-impact action and needs explicit user approval")]
        return []


def _value_forms(v: Any) -> list[str]:
    if isinstance(v, bool):
        return [str(v).lower()]
    if isinstance(v, (int, float)):
        forms = {str(v), f"{v:,}"}
        if float(v).is_integer():
            forms |= {str(int(v)), f"{int(v):,}", f"{v:.2f}"}
        return sorted(forms)
    if isinstance(v, str):
        return [v.strip().lower()]
    if isinstance(v, list):
        return [x.strip().lower() for x in v if isinstance(x, str)]
    return []
