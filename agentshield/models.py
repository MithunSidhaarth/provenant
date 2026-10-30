"""Core data types shared by the policy engine, gateway, agent and audit log."""
from __future__ import annotations

import enum
import hashlib
import json
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any


class Decision(str, enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


# Precedence used when combining rule outcomes: the most restrictive wins.
_SEVERITY = {Decision.ALLOW: 0, Decision.REQUIRE_APPROVAL: 1, Decision.DENY: 2}


def most_restrictive(decisions: list[Decision]) -> Decision:
    if not decisions:
        # No rule produced an opinion: that is an unsupported situation, so fail closed.
        return Decision.DENY
    return max(decisions, key=lambda d: _SEVERITY[d])


def canonical_json(obj: Any) -> str:
    """Stable serialisation used for hashing (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


@dataclass
class ToolCall:
    """A tool invocation proposed by the agent. Nothing here is trusted."""

    tool: Any
    args: Any
    session_id: str
    agent_id: str
    call_id: str = field(default_factory=lambda: new_id("call"))
    # The agent may say why it wants to make the call. Used as evidence only, never to grant.
    rationale: str = ""

    def fingerprint(self) -> str:
        """Hash binding an approval to this exact tool + arguments."""
        return sha256_hex(canonical_json({"tool": self.tool, "args": self.args,
                                          "session_id": self.session_id, "agent_id": self.agent_id}))

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    rule: str
    decision: Decision
    reason: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"rule": self.rule, "decision": self.decision.value,
                "reason": self.reason, "evidence": self.evidence}


@dataclass
class PolicyResult:
    decision: Decision
    findings: list[Finding]
    call_fingerprint: str
    policy_version: str

    @property
    def reasons(self) -> list[str]:
        return [f.reason for f in self.findings if f.decision != Decision.ALLOW]

    def to_dict(self) -> dict:
        return {"decision": self.decision.value,
                "findings": [f.to_dict() for f in self.findings],
                "reasons": self.reasons,
                "call_fingerprint": self.call_fingerprint,
                "policy_version": self.policy_version}
