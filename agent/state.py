"""
AgentState — a snapshot of what the agent knows at the start of each iteration.

Read fresh from DB every observe step so it always reflects reality, not
the agent's cached beliefs. The agent cannot modify scope, cannot mark itself
as in-scope, and cannot see raw tool output — only structured DB records.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID

from database.models import AiAssessment, Finding, Host


@dataclass
class CompletedAction:
    action: str
    target: str
    rationale: str
    new_events: int
    summary: str


@dataclass
class AgentState:
    scan_id: UUID
    target_domain: str
    iteration: int
    max_iterations: int

    # Structured DB records — no raw content, no response bodies.
    hosts: list[Host] = field(default_factory=list)
    assessments: list[AiAssessment] = field(default_factory=list)   # host triage results
    findings: list[Finding] = field(default_factory=list)

    # Session history — what the agent has already done.
    completed_actions: list[CompletedAction] = field(default_factory=list)

    # Productivity signal for stopping-condition checks.
    total_agent_events: int = 0   # cumulative events from agent actions (not initial enum)

    @property
    def iterations_remaining(self) -> int:
        return max(0, self.max_iterations - self.iteration)

    @property
    def consecutive_zero_event_actions(self) -> int:
        """How many recent consecutive actions produced zero new events."""
        count = 0
        for action in reversed(self.completed_actions):
            if action.new_events == 0:
                count += 1
            else:
                break
        return count

    def assessment_for(self, hostname: str) -> AiAssessment | None:
        host = next((h for h in self.hosts if h.hostname == hostname), None)
        if host is None:
            return None
        return next((a for a in self.assessments if a.target_id == host.id), None)
