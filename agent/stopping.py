"""Stopping conditions for the agent loop."""

from __future__ import annotations

import enum
from dataclasses import dataclass

from agent.state import AgentState


class StopReason(str, enum.Enum):
    MAX_ITERATIONS = "max_iterations"
    TIMEOUT = "timeout"
    DIMINISHING_RETURNS = "diminishing_returns"
    AGENT_DECIDED = "agent_decided"          # model chose "stop"
    NO_HOSTS = "no_hosts"                    # nothing to investigate


@dataclass
class StoppingConditions:
    max_iterations: int = 20
    max_minutes: float = 15.0
    # Stop if this many consecutive actions produce zero new events.
    zero_event_streak: int = 3

    def check(self, state: AgentState, elapsed_seconds: float) -> StopReason | None:
        if not state.hosts:
            return StopReason.NO_HOSTS

        if state.iteration >= self.max_iterations:
            return StopReason.MAX_ITERATIONS

        if elapsed_seconds >= self.max_minutes * 60:
            return StopReason.TIMEOUT

        if (
            len(state.completed_actions) >= self.zero_event_streak
            and state.consecutive_zero_event_actions >= self.zero_event_streak
        ):
            return StopReason.DIMINISHING_RETURNS

        return None
