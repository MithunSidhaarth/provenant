from agentshield.audit import AuditLog
from agentshield.gateway import Gateway
from agentshield.models import ToolCall
from agentshield.policy import PolicyEngine
from agentshield.sandbox import World, VAULT
from agentshield.tools import ToolRegistry

AGENT = "support-agent"


def make_gateway(engine=None, clock=None, **kw):
    world = World()
    registry = ToolRegistry(world)
    audit = AuditLog(redact=VAULT)
    gw = Gateway(engine or PolicyEngine.from_file(), registry, audit, clock=clock or __import__("time").time, **kw)
    return gw, world, audit


def call(ctx, tool, **args):
    return ToolCall(tool=tool, args=args, session_id=ctx.session_id, agent_id=ctx.agent_id)
