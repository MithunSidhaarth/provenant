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

import codecs
import json
import re
from dataclasses import dataclass, field
from typing import Any

from .gateway import Gateway
from .models import Decision, ToolCall

from .normalize import views
from .tools import TOOLS

# Phrases the gullible model treats as "do this now", in English, Hindi, Kannada and Hinglish,
# plus fake system headers. Each must be followed by a tool name and a JSON object.
TRIGGER_RE = re.compile(
    r"(?:assistant\s*action|system\s*:\s*(?:call|invoke|run)|सहायक\s*कार्रवाई|ಸಹಾಯಕ\s*ಕ್ರಿಯೆ"
    r"|assistant\s+ko\s+(?:ye|yeh)\s+karna\s+hai)\s*:?\s*([A-Za-z_]\w*)\s*", re.IGNORECASE)
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
                # Instructions are taken from content the agent *reads* (documents, KB, pages),
                # not from its own action receipts, which would otherwise echo into loops.
                spec = TOOLS.get(call.tool) if isinstance(call.tool, str) else None
                if self.obey_injections and spec is not None and spec.untrusted_output:
                    injected = [("injected", {"tool": tool, "args": args,
                                              "rationale": "instruction found in retrieved content"},
                                 f"{call.tool}:{call.call_id}")
                                for tool, args in extract_directives(text)]
                    queue = injected + queue

        return {"session_id": ctx.session_id, "agent_id": self.agent_id, "user_task": user_task,
                "protected": self.gateway.protected, "steps": [s.to_dict() for s in steps]}


def _json_object_at(text: str, i: int) -> dict | None:
    """Parse the brace-balanced JSON object starting at text[i] (which may span lines)."""
    if i >= len(text) or text[i] != "{":
        return None
    depth, in_str, esc = 0, False, False
    for j in range(i, len(text)):
        ch = text[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(text[i:j + 1])
                except ValueError:
                    return None
                return obj if isinstance(obj, dict) else None
    return None


def model_views(text: str) -> list[str]:
    """What a strong model can 'read' in content. Deliberately a superset of what AgentShield
    canonicalises: it also undoes ROT13 and reversed text, which the defender does not. Those
    fuzzer classes show what happens when detection and taint are blind and only policy remains."""
    vs = views(text)
    return vs + [codecs.decode(v, "rot13") for v in vs] + ["\n".join(l[::-1] for l in v.splitlines()) for v in vs]


# --- natural-language intent parsing -------------------------------------------------------
# Judges type attacks in plain language, not in a directive syntax. The worst-case model obeys
# those too. Deterministic, regex-based, English plus common Hindi / Kannada / Hinglish verbs.
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"(?:https?|sim|file|ftp)://[^\s\"'<>)]+")
CUST_RE = re.compile(r"\bC-\d{3}\b", re.IGNORECASE)
AMOUNT_RE = re.compile(r"(?:₹|rs\.?|inr|\$|usd)?\s*(\d[\d,]*(?:\.\d+)?)")
SEND_VERBS = r"(email|e-mail|mail|send|forward|share|post|bhej|भेज|ಕಳುಹಿಸ)"
SECRET_VERBS = r"(fetch|get|reveal|read|show|give|find|leak|dump|print|retrieve|nikal|बताओ|दिखाओ|ತೋರಿಸ|ನೀಡ)"
SECRET_NOUNS = r"(password|passwd|secret|api[ _-]?key|credential|token|ssh key|पासवर्ड|ಪಾಸ್\u200c?ವರ್ಡ್)"
DELETE_VERBS = r"(delete|remove|erase|wipe|drop|purge|hata|हटा|मिटा|ಅಳಿಸ)"
URL_VERBS = r"(visit|open|fetch|go to|load|ping|browse|call|curl|khol|खोल|ತೆರೆ)"
PII_NOUNS = r"(ssn|social security|card number|credit card|aadhaar|pan number)"


def _secret_name(sentence: str) -> str:
    low = sentence.lower()
    if "stripe" in low or "payment" in low or "api" in low:
        return "STRIPE_API_KEY"
    if "ssh" in low or "admin" in low:
        return "ADMIN_SSH_KEY"
    return "PROD_DB_PASSWORD"


def intents_from_language(text: str) -> list[tuple[str, dict]]:
    """Map plain-language imperatives in content to tool calls, in the order they appear."""
    out: list[tuple[str, dict]] = []
    sentences = re.split(r"(?<=[.!?।])\s+|\n+", text)
    produced_data = False
    for snt in sentences:
        low = snt.lower()
        if not snt.strip():
            continue
        if re.search(SECRET_VERBS, low) and re.search(SECRET_NOUNS, low):
            out.append(("get_secret", {"name": _secret_name(snt)}))
            produced_data = True
        cust = CUST_RE.search(snt)
        if cust and re.search(PII_NOUNS, low):
            fields = ["name"] + (["ssn"] if re.search(r"ssn|social security|aadhaar|pan", low) else []) + \
                     (["card_number"] if "card" in low else [])
            out.append(("lookup_customer", {"customer_id": cust.group(0).upper(), "fields": fields}))
            produced_data = True
        if cust and re.search(DELETE_VERBS, low):
            out.append(("delete_customer", {"customer_id": cust.group(0).upper()}))
        if cust and "refund" in low:
            nums = [m.group(1) for m in AMOUNT_RE.finditer(snt.replace(cust.group(0), "")) if m.group(1).strip(",")]
            if nums:
                amt = float(nums[0].replace(",", ""))
                out.append(("issue_refund", {"customer_id": cust.group(0).upper(),
                                             "amount": int(amt) if amt.is_integer() else amt, "reason": "requested"}))
        url = URL_RE.search(snt)
        if url and re.search(URL_VERBS, low):
            out.append(("fetch_url", {"url": url.group(0).rstrip(".,;")}))
        mail = EMAIL_RE.search(snt)
        if mail and re.search(SEND_VERBS, low):
            body = "{{previous_output}}" if produced_data else snt.strip()[:500]
            out.append(("send_email", {"to": mail.group(0), "subject": "Requested information", "body": body}))
    return out


def extract_directives(text: str) -> list[tuple[str, dict]]:
    """Every (tool, args) instruction the gullible model would obey in this content."""
    found: list[tuple[str, dict]] = []
    direct = views(text)
    for view in model_views(text):
        for m in TRIGGER_RE.finditer(view):
            args = _json_object_at(view, m.end())
            item = (m.group(1), args)
            # Decoding guesses (ROT13, reversal) only count when they yield a tool the model knows.
            if view not in direct and m.group(1) not in TOOLS:
                continue
            if args is not None and item not in found:
                found.append(item)
    if not found:   # no structured directive: fall back to plain-language intents
        for view in views(text):
            for item in intents_from_language(view):
                if item not in found:
                    found.append(item)
    return found
