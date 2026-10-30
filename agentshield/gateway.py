"""The tool gateway: the single path from an agent's proposed call to a tool's execution.

    agent ──proposes──▶ Gateway.invoke ──▶ PolicyEngine.evaluate ──▶ decision
                                 │ALLOW: mint single-use grant ──▶ ToolRegistry.execute
                                 │REQUIRE_APPROVAL: store pending request, execute nothing
                                 │DENY: execute nothing
                                 └──▶ AuditLog (request, decision, reasons, outcome)

UnprotectedGateway is the "before" baseline used by the before/after tests: same agent, same
tools, same simulated world, but no policy. It exists to prove the attack scenarios are real.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from .audit import AuditLog
from .detectors import scan_injection
from .models import Decision, Finding, PolicyResult, ToolCall, new_id
from .policy import PolicyEngine, SessionContext
from .tools import ToolRegistry

MAX_LOGGED_OUTPUT = 4000


@dataclass
class InvokeResult:
    call: ToolCall
    decision: Decision
    reasons: list[str]
    findings: list[dict]
    executed: bool
    output: Any = None
    error: str | None = None
    approval_id: str | None = None
    injection_indicators: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"call": self.call.to_dict(), "decision": self.decision.value, "reasons": self.reasons,
                "findings": self.findings, "executed": self.executed, "output": self.output,
                "error": self.error, "approval_id": self.approval_id,
                "injection_indicators": self.injection_indicators}


@dataclass
class PendingApproval:
    approval_id: str
    call: ToolCall
    fingerprint: str
    created_at: float
    expires_at: float
    call_count_at_request: int
    policy: dict
    status: str = "pending"          # pending | approved | rejected | expired | failed
    decided_by: str | None = None
    result: dict | None = None

    def to_dict(self) -> dict:
        return {"approval_id": self.approval_id, "call": self.call.to_dict(), "fingerprint": self.fingerprint,
                "created_at": self.created_at, "expires_at": self.expires_at, "status": self.status,
                "decided_by": self.decided_by, "policy": self.policy, "result": self.result}


def _clip(obj: Any) -> Any:
    text = json.dumps(obj, ensure_ascii=False, default=str)
    return obj if len(text) <= MAX_LOGGED_OUTPUT else {"truncated": text[:MAX_LOGGED_OUTPUT]}


def _output_text(output: Any) -> str:
    return output if isinstance(output, str) else json.dumps(output, ensure_ascii=False, default=str)


class Gateway:
    protected = True

    def __init__(self, engine: PolicyEngine, registry: ToolRegistry, audit: AuditLog,
                 approval_ttl: float | None = None, clock=time.time) -> None:
        self.engine = engine
        self.registry = registry
        self.audit = audit
        self.sessions: dict[str, SessionContext] = {}
        self.approvals: dict[str, PendingApproval] = {}
        self.clock = clock
        self.approval_ttl = approval_ttl or float(engine.config.get("approval_ttl_seconds", 900))

    # --- sessions ----------------------------------------------------------------------
    def open_session(self, agent_id: str, user_task: str, session_id: str | None = None) -> SessionContext:
        sid = session_id or new_id("sess")
        ctx = SessionContext(session_id=sid, agent_id=agent_id, user_task=user_task,
                             known_secrets=dict(self.registry.world.vault))
        self.sessions[sid] = ctx
        self.audit.append("session_start", sid, {"agent_id": agent_id, "user_task": user_task,
                                                 "protected": self.protected,
                                                 "policy_version": self.engine.version})
        return ctx

    def ingest_untrusted(self, ctx: SessionContext, source: str, output: Any) -> list[dict]:
        """Record content the agent has seen that did not come from the user."""
        text = _output_text(output)
        ctx.untrusted_texts.append(text)
        flags = scan_injection(text)
        for f in flags:
            f["source"] = source
        ctx.injection_flags.extend(flags)
        return flags

    # --- invocation --------------------------------------------------------------------
    def invoke(self, call: ToolCall) -> InvokeResult:
        ctx = self.sessions.get(call.session_id) if isinstance(call.session_id, str) else None
        self.audit.append("tool_request", str(call.session_id),
                          {"call_id": call.call_id, "tool": call.tool, "args": call.args,
                           "agent_id": call.agent_id, "rationale": call.rationale})
        if ctx is None:
            return self._deny_without_policy(call, "unknown or closed session; failing closed")

        try:
            result = self.engine.evaluate(call, ctx)
            if not isinstance(result, PolicyResult) or not isinstance(result.decision, Decision):
                raise TypeError("policy engine returned an unsupported decision")
        except Exception as exc:
            return self._deny_without_policy(call, f"policy evaluation failed ({type(exc).__name__}); failing closed")

        ctx.call_count += 1
        self.audit.append("policy_decision", ctx.session_id,
                          {"call_id": call.call_id, "tool": call.tool, **result.to_dict()})

        if result.decision == Decision.ALLOW:
            return self._execute(call, ctx, result)
        if result.decision == Decision.REQUIRE_APPROVAL:
            now = self.clock()
            pa = PendingApproval(new_id("appr"), call, result.call_fingerprint, now, now + self.approval_ttl,
                                 ctx.call_count - 1, result.to_dict())
            self.approvals[pa.approval_id] = pa
            self.audit.append("approval_requested", ctx.session_id,
                              {"approval_id": pa.approval_id, "call_id": call.call_id, "tool": call.tool,
                               "fingerprint": pa.fingerprint, "expires_at": pa.expires_at})
            return InvokeResult(call, result.decision, result.reasons, result.to_dict()["findings"],
                                executed=False, approval_id=pa.approval_id)
        return InvokeResult(call, Decision.DENY, result.reasons, result.to_dict()["findings"], executed=False,
                            error="denied by policy")

    def _deny_without_policy(self, call: ToolCall, reason: str) -> InvokeResult:
        f = Finding("gateway", Decision.DENY, reason)
        self.audit.append("policy_decision", str(call.session_id),
                          {"call_id": call.call_id, "tool": call.tool, "decision": "DENY",
                           "reasons": [reason], "findings": [f.to_dict()]})
        return InvokeResult(call, Decision.DENY, [reason], [f.to_dict()], executed=False, error="denied")

    def _execute(self, call: ToolCall, ctx: SessionContext, result: PolicyResult,
                 approval_id: str | None = None) -> InvokeResult:
        grant = self.registry.mint_grant(result.call_fingerprint)
        try:
            output = self.registry.execute(grant, call)
        except Exception as exc:
            self.audit.append("tool_error", ctx.session_id, {"call_id": call.call_id, "tool": call.tool,
                                                             "error": f"{type(exc).__name__}: {exc}"})
            return InvokeResult(call, result.decision, result.reasons, result.to_dict()["findings"],
                                executed=False, error=str(exc), approval_id=approval_id)
        spec = self.registry.spec(call.tool)
        flags = self.ingest_untrusted(ctx, f"{call.tool}:{call.call_id}", output) if spec.untrusted_output else []
        self.audit.append("tool_result", ctx.session_id,
                          {"call_id": call.call_id, "tool": call.tool, "approval_id": approval_id,
                           "trust": "untrusted" if spec.untrusted_output else "system",
                           "injection_indicators": flags, "output": _clip(output)})
        # Untrusted output is handed back explicitly labelled as data, never as instructions.
        wrapped = {"trust": "untrusted-data", "content": output} if spec.untrusted_output else output
        return InvokeResult(call, result.decision, result.reasons, result.to_dict()["findings"],
                            executed=True, output=wrapped, approval_id=approval_id, injection_indicators=flags)

    # --- approvals ---------------------------------------------------------------------
    def pending(self) -> list[PendingApproval]:
        self._expire()
        return [p for p in self.approvals.values() if p.status == "pending"]

    def _expire(self) -> None:
        now = self.clock()
        for p in self.approvals.values():
            if p.status == "pending" and now >= p.expires_at:
                p.status = "expired"
                self.audit.append("approval_expired", p.call.session_id, {"approval_id": p.approval_id})

    def decide(self, approval_id: str, approver: str, approve: bool, note: str = "") -> dict:
        """Apply a human decision. Returns {ok, status, reason, result}."""
        self._expire()
        pa = self.approvals.get(approval_id)
        if pa is None:
            return {"ok": False, "status": "unknown", "reason": "no such approval request"}
        sid = pa.call.session_id

        def refuse(reason: str) -> dict:
            self.audit.append("approval_refused", sid, {"approval_id": approval_id, "approver": approver,
                                                        "reason": reason})
            return {"ok": False, "status": pa.status, "reason": reason}

        if pa.status != "pending":
            return refuse(f"request is already {pa.status}")
        if not isinstance(approver, str) or not approver.startswith("human:") or len(approver) < 7:
            return refuse("approvals must come from a named human approver, not an agent")
        if approver[6:] in self.engine.config.get("agents", {}):
            return refuse("an agent cannot approve its own requests")
        if not approve:
            pa.status, pa.decided_by = "rejected", approver
            self.audit.append("approval_rejected", sid, {"approval_id": approval_id, "approver": approver,
                                                         "note": note})
            return {"ok": True, "status": "rejected", "reason": "rejected by approver"}

        # The approval is bound to the exact call. If anything changed, it is void.
        if pa.call.fingerprint() != pa.fingerprint:
            pa.status = "failed"
            return refuse("call was modified after the approval request was created")

        # Re-evaluate under current policy: approval can lift REQUIRE_APPROVAL, never DENY.
        ctx = self.sessions.get(sid)
        if ctx is None:
            pa.status = "failed"
            return refuse("session no longer exists")
        saved = ctx.call_count
        ctx.call_count = pa.call_count_at_request
        try:
            result = self.engine.evaluate(pa.call, ctx)
        finally:
            ctx.call_count = saved
        if result.decision != Decision.REQUIRE_APPROVAL:
            pa.status = "failed"
            return refuse(f"re-evaluation returned {result.decision.value}; approval cannot override it")

        pa.status, pa.decided_by = "approved", approver
        self.audit.append("approval_granted", sid, {"approval_id": approval_id, "approver": approver,
                                                    "fingerprint": pa.fingerprint, "note": note})
        res = self._execute(pa.call, ctx, result, approval_id=approval_id)
        pa.result = res.to_dict()
        return {"ok": res.executed, "status": "approved", "reason": "approved and executed" if res.executed
                else f"approved but execution failed: {res.error}", "result": pa.result}


class UnprotectedGateway(Gateway):
    """Baseline with no enforcement: executes whatever the agent proposes (inside the sandbox)."""

    protected = False

    def invoke(self, call: ToolCall) -> InvokeResult:
        ctx = self.sessions.get(call.session_id) if isinstance(call.session_id, str) else None
        sid = str(call.session_id)
        self.audit.append("tool_request", sid, {"call_id": call.call_id, "tool": call.tool, "args": call.args,
                                                "agent_id": call.agent_id, "unprotected": True})
        spec = self.registry.spec(call.tool)
        if ctx is None or spec is None or not isinstance(call.args, dict):
            err = "tool does not exist in the simulation" if spec is None else "malformed call"
            self.audit.append("tool_error", sid, {"call_id": call.call_id, "error": err})
            return InvokeResult(call, Decision.ALLOW, ["no policy enforced"], [], executed=False, error=err)
        grant = self.registry.mint_grant(call.fingerprint())
        try:
            output = self.registry.execute(grant, call)
        except Exception as exc:
            self.audit.append("tool_error", sid, {"call_id": call.call_id, "error": f"{type(exc).__name__}: {exc}"})
            return InvokeResult(call, Decision.ALLOW, ["no policy enforced"], [], executed=False, error=str(exc))
        flags = self.ingest_untrusted(ctx, f"{call.tool}:{call.call_id}", output) if spec.untrusted_output else []
        self.audit.append("tool_result", sid, {"call_id": call.call_id, "tool": call.tool, "unprotected": True,
                                               "output": _clip(output)})
        return InvokeResult(call, Decision.ALLOW, ["no policy enforced"], [], executed=True, output=output,
                            injection_indicators=flags)
