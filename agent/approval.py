"""
Approval gate — decides whether an agent action is allowed to execute.

Phase 4 tools are all low-risk so AUTO always approves. INTERACTIVE mode
prompts the human via stdin (useful for local sessions; not suitable for
headless/CI runs). Future phases add HIGH-risk actions that require explicit
approval regardless of mode.
"""

from __future__ import annotations

import asyncio
import enum
import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)


class ApprovalMode(str, enum.Enum):
    AUTO = "auto"               # approve all Phase 4 (low-risk) actions
    INTERACTIVE = "interactive" # prompt user; useful for local exploratory sessions


@dataclass
class AgentDecision:
    action: str
    target: str
    rationale: str
    stop_reason: str = ""


class ApprovalGate:
    def __init__(self, mode: ApprovalMode = ApprovalMode.AUTO) -> None:
        self._mode = mode

    async def check(self, decision: AgentDecision) -> bool:
        """Return True if the action may proceed."""
        if decision.action == "stop":
            return True   # stop is always allowed

        if self._mode is ApprovalMode.AUTO:
            log.info("[approve] auto: %s(%s)", decision.action, decision.target)
            return True

        # INTERACTIVE: ask the human.
        prompt = (
            f"\n[agent] proposed action:\n"
            f"  action   : {decision.action}\n"
            f"  target   : {decision.target}\n"
            f"  rationale: {decision.rationale}\n"
            f"Approve? [y/N] "
        )
        loop = asyncio.get_event_loop()
        answer = await loop.run_in_executor(None, lambda: input(prompt))
        approved = answer.strip().lower() == "y"
        if not approved:
            log.info("[approve] human rejected %s(%s)", decision.action, decision.target)
        return approved
