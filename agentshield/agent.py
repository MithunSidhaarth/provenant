"""A simulated AI agent with a deliberately gullible "model".

The model turns the user's request into a plan of tool calls (provided by the scenario, so the
demo is deterministic and works with no model API). Crucially, it also *obeys instructions it
finds in tool output*: any line of the form

    ASSISTANT ACTION: <tool> {json args}

in a document, KB article or web page is appended to its plan. This models the worst case for
prompt injection: an LLM that cannot tell data from instructions. AgentShield must stay safe
even with this model, which is the point: the model is not the security boundary.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from .gateway import Gateway
from .models import Decision, ToolCall

DIRECTIVE_RE = re.compile(r"ASSISTANT ACTION:\s*([A-Za-z_][\w]*)\s*(\{.*\})", re.IGNORECASE)
MAX_STEPS = 15


@dataclass
class Step:
    index: int
    source: str            # "user_plan" | "injected" | "malformed"
    result: dict | None = None
    skipped: str | None = None
    injected_from: str | None = None

    def to_dict(self) -> dict:
        return {"index": self.index, "source": self.source, "result": self.result,
                "skipped": self.skipped, "injected_from": self.injected_from}


def _summarise(text: str, limit: int = 280) -> str:
    lines = [l.strip() for l in text.splitlines()
             if l.strip() and "ASSISTANT ACTION" not in l.upper() and not l.strip().startswith(("<!--", "#"))]
    out = " ".join(lines)
    return out[:limit] + ("…" if len(out) > limit else "")


def _content_of(output: Any) -> Any:
    if isinstance(output, dict) and output.get("trust") == "untrusted-data":
        return output["content"]
    return output


class SimulatedAgent:
    def __init__(self, gateway: Gateway, agent_id: str, obey_injections: bool = True) -> None:
        self.gateway = gateway
        self.agent_id = agent_id
        self.obey_injections = obey_injections

    def _render(self, value: Any, last: dict | None, last_text: str) -> Any:
        if isinstance(value, str):
            if last and last["executed"]:
                prev = json.dumps(_content_of(last["output"]), ensure_ascii=False)
            else:
                prev = f"(previous step failed: {last['error']})" if last else ""
            return value.replace("{{previous_output}}", prev).replace("{{summary}}", _summarise(last_text))
        if isinstance(value, dict):
            return {k: self._render(v, last, last_text) for k, v in value.items()}
        if isinstance(value, list):
            return [self._render(v, last, last_text) for v in value]
        return value

    def run(self, user_task: str, plan: list[dict], session_id: str | None = None,
            prior_context: str | None = None) -> dict:
        ctx = self.gateway.open_session(self.agent_id, user_task, session_id)
        if prior_context:   # content already in the agent's context window, e.g. a pasted email
            self.gateway.ingest_untrusted(ctx, "prior_context", prior_context)
        queue: list[tuple[str, dict, str | None]] = [
            (p.get("source", "malformed") if "raw" in p else "user_plan", p, None) for p in plan]
        steps: list[Step] = []
        last: dict | None = None
        last_text = ""

        while queue and len(steps) < MAX_STEPS:
            source, item, origin = queue.pop(0)
            step = Step(len(steps), source, injected_from=origin)
            steps.append(step)

            if "raw" in item:      # a malformed proposal from a confused model, passed through verbatim
                raw = item["raw"]
                call = ToolCall(tool=raw.get("tool"), args=raw.get("args"),
                                session_id=raw.get("session_id", ctx.session_id),
                                agent_id=raw.get("agent_id", self.agent_id), rationale=item.get("rationale", ""))
            else:
                if item.get("requires_previous") and not (last and last["executed"]):
                    step.skipped = "depends on the previous step's output, which was not produced"
                    continue
                call = ToolCall(tool=item["tool"], args=self._render(item.get("args", {}), last, last_text),
                                session_id=ctx.session_id, agent_id=self.agent_id,
                                rationale=item.get("rationale", ""))

            res = self.gateway.invoke(call)
            step.result = res.to_dict()
            last = step.result
            if res.executed:
                content = _content_of(res.output)
                text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
                if isinstance(content, dict) and isinstance(content.get("content"), str):
                    text = content["content"]
                elif isinstance(content, dict) and isinstance(content.get("results"), list):
                    text = "\n".join(r.get("body", "") for r in content["results"])
                last_text = text
                if self.obey_injections:
                    injected = [("injected", {"tool": m.group(1), "args": json.loads(m.group(2)),
                                              "rationale": "instruction found in retrieved content"},
                                 f"{call.tool}:{call.call_id}")
                                for m in DIRECTIVE_RE.finditer(text) if _is_json(m.group(2))]
                    queue = injected + queue

        return {"session_id": ctx.session_id, "agent_id": self.agent_id, "user_task": user_task,
                "protected": self.gateway.protected, "steps": [s.to_dict() for s in steps]}


def _is_json(s: str) -> bool:
    try:
        return isinstance(json.loads(s), dict)
    except ValueError:
        return False
