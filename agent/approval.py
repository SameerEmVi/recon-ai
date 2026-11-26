"""
Approval gate — decides whether an agent action is allowed to execute.

Actions carry a **risk level** derived from the tool's capability (see
`agent.tools.tool_risk`): a vulnerability-check or intrusive action is `high`,
everything else `low`. The gate's behaviour depends on its mode:

  - **AUTO** — approve every action (the recon agent default; unchanged). Use
    only where the operator has pre-authorized autonomous low-and-slow recon.
  - **REVIEW** — approve `low` actions automatically, require explicit sign-off
    for `high` ones. This is the agent-driven pentest section's gate
    (docs/pentest-section-design.md §7.4): the operator approves each testing
    step. **Fail-closed:** a `high` action with no approver wired is *denied*,
    never run.
  - **INTERACTIVE** — ask for every non-stop action (stdin by default; a local
    exploratory session).

An `approver` callable — `async (AgentDecision) -> bool` — is the plug point a UI
(the dashboard) provides so a human signs off out-of-band. Without one, REVIEW
falls back to the stdin prompt for `high` actions when a TTY is available, else
denies (fail-closed). `stop` is always allowed.
"""

from __future__ import annotations

import asyncio
import enum
import logging
import sys
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

log = logging.getLogger(__name__)

RISK_LOW = "low"
RISK_HIGH = "high"


class ApprovalMode(str, enum.Enum):
    AUTO = "auto"               # approve all actions (pre-authorized autonomous recon)
    REVIEW = "review"           # auto low-risk, explicit sign-off for high-risk (pentest)
    INTERACTIVE = "interactive" # prompt for every non-stop action


@dataclass
class AgentDecision:
    action: str
    target: str
    rationale: str
    stop_reason: str = ""
    risk: str = RISK_LOW


Approver = Callable[[AgentDecision], Awaitable[bool]]


class ApprovalGate:
    def __init__(self, mode: ApprovalMode = ApprovalMode.AUTO,
                 approver: Optional[Approver] = None) -> None:
        self._mode = mode
        self._approver = approver

    async def _prompt_stdin(self, decision: AgentDecision) -> bool:
        prompt = (
            f"\n[agent] proposed action (risk={decision.risk}):\n"
            f"  action   : {decision.action}\n"
            f"  target   : {decision.target}\n"
            f"  rationale: {decision.rationale}\n"
            f"Approve? [y/N] "
        )
        loop = asyncio.get_event_loop()
        answer = await loop.run_in_executor(None, lambda: input(prompt))
        return answer.strip().lower() == "y"

    async def _review_high(self, decision: AgentDecision) -> bool:
        """Sign-off for a high-risk action: the wired approver, else a stdin
        prompt when a TTY is available, else fail-closed (deny — never auto-run
        a vuln/intrusive action unattended)."""
        if self._approver is not None:
            return bool(await self._approver(decision))
        if sys.stdin and sys.stdin.isatty():
            return await self._prompt_stdin(decision)
        log.warning("[approve] high-risk %s(%s) denied — no approver and no TTY "
                    "(fail-closed)", decision.action, decision.target)
        return False

    async def _ask_interactive(self, decision: AgentDecision) -> bool:
        """Prompt for every action: the wired approver, else stdin (the original
        local-session behaviour — not for headless/CI runs)."""
        if self._approver is not None:
            return bool(await self._approver(decision))
        return await self._prompt_stdin(decision)

    async def check(self, decision: AgentDecision) -> bool:
        """Return True if the action may proceed."""
        if decision.action == "stop":
            return True

        if self._mode is ApprovalMode.AUTO:
            log.info("[approve] auto: %s(%s)", decision.action, decision.target)
            return True

        if self._mode is ApprovalMode.REVIEW:
            if decision.risk != RISK_HIGH:
                log.info("[approve] review: auto-approved low-risk %s(%s)",
                         decision.action, decision.target)
                return True
            approved = await self._review_high(decision)
            log.info("[approve] review: high-risk %s(%s) %s",
                     decision.action, decision.target,
                     "approved" if approved else "rejected")
            return approved

        # INTERACTIVE: ask for every action.
        approved = await self._ask_interactive(decision)
        if not approved:
            log.info("[approve] human rejected %s(%s)", decision.action, decision.target)
        return approved
