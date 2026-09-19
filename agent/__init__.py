"""Agent package — Phase 4 constrained agentic loop."""

from agent.approval import ApprovalGate, ApprovalMode, AgentDecision
from agent.loop import AgentLoop, AgentResult
from agent.state import AgentState, CompletedAction
from agent.stopping import StopReason, StoppingConditions
from agent.tools import build_tool_registry

__all__ = [
    "ApprovalGate",
    "ApprovalMode",
    "AgentDecision",
    "AgentLoop",
    "AgentResult",
    "AgentState",
    "CompletedAction",
    "StopReason",
    "StoppingConditions",
    "build_tool_registry",
]
