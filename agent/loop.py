"""
AgentLoop — the decide→approve→act→observe cycle for Phase 4.

One iteration:
  1. observe  — read current DB state into AgentState
  2. decide   — ask the LLM (via Assessor + forced tool call) for next action
  3. approve  — pass through ApprovalGate (auto or interactive)
  4. act      — run the chosen AgentTool
  5. record   — append CompletedAction to state history

The loop terminates when StoppingConditions.check() returns a reason
or the LLM chooses action="stop".
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from uuid import UUID

log = logging.getLogger(__name__)


@dataclass
class AgentResult:
    stop_reason: str
    iterations: int
    total_new_events: int
    completed_actions: list  # list[CompletedAction]


class AgentLoop:
    def __init__(
        self,
        *,
        controller,          # ScanController
        host_repo,           # HostRepository
        finding_repo,        # FindingRepository
        assessment_repo,     # AiAssessmentRepository
        assessor,            # Assessor
        stopping,            # StoppingConditions
        approval_gate,       # ApprovalGate
        tool_registry: dict, # {name: AgentTool}
        max_iterations: int = 20,
    ) -> None:
        self._controller = controller
        self._host_repo = host_repo
        self._finding_repo = finding_repo
        self._assessment_repo = assessment_repo
        self._assessor = assessor
        self._stopping = stopping
        self._gate = approval_gate
        self._tools = tool_registry
        self._max_iterations = max_iterations

    async def run(self, scan_id: UUID, target_domain: str) -> AgentResult:
        from agent.approval import AgentDecision
        from agent.state import AgentState, CompletedAction
        from agent.stopping import StopReason
        from ai.prompts.agent import AGENT_DECISION_TOOL, build_agent_prompt
        from ai.prompts.system import SYSTEM_PROMPT

        start = time.monotonic()
        completed: list[CompletedAction] = []
        total_new = 0
        iteration = 0

        while True:
            # ── observe ───────────────────────────────────────────────────────
            hosts = await self._host_repo.list_for_scan(scan_id)
            findings = await self._finding_repo.list_for_scan(scan_id)
            assessments = await self._assessment_repo.list_for_scan(scan_id)

            state = AgentState(
                scan_id=scan_id,
                target_domain=target_domain,
                iteration=iteration,
                max_iterations=self._max_iterations,
                hosts=hosts,
                assessments=assessments,
                findings=findings,
                completed_actions=completed,
                total_agent_events=total_new,
            )

            # ── stopping conditions ───────────────────────────────────────────
            elapsed = time.monotonic() - start
            stop_reason = self._stopping.check(state, elapsed)
            if stop_reason is not None:
                log.info("[agent] stopping: %s", stop_reason)
                return AgentResult(
                    stop_reason=stop_reason.value,
                    iterations=iteration,
                    total_new_events=total_new,
                    completed_actions=completed,
                )

            # ── decide ────────────────────────────────────────────────────────
            prompt = build_agent_prompt(state)
            log.info("[agent] iteration %d — calling LLM for decision", iteration)

            raw = await self._assessor.call(
                prompt,
                AGENT_DECISION_TOOL,
                system=SYSTEM_PROMPT,
            )

            if not raw:
                log.warning("[agent] LLM returned empty decision — stopping")
                return AgentResult(
                    stop_reason="llm_error",
                    iterations=iteration,
                    total_new_events=total_new,
                    completed_actions=completed,
                )

            action = str(raw.get("action", "stop"))
            target = str(raw.get("target", ""))
            rationale = str(raw.get("rationale", ""))
            stop_reason_str = str(raw.get("stop_reason", ""))

            decision = AgentDecision(
                action=action,
                target=target,
                rationale=rationale,
                stop_reason=stop_reason_str,
            )

            if action == "stop":
                log.info("[agent] LLM decided to stop: %s", stop_reason_str or rationale)
                return AgentResult(
                    stop_reason=StopReason.AGENT_DECIDED.value,
                    iterations=iteration,
                    total_new_events=total_new,
                    completed_actions=completed,
                )

            # ── approve ───────────────────────────────────────────────────────
            approved = await self._gate.check(decision)
            if not approved:
                log.info("[agent] action rejected by approval gate — stopping")
                return AgentResult(
                    stop_reason="rejected_by_gate",
                    iterations=iteration,
                    total_new_events=total_new,
                    completed_actions=completed,
                )

            # ── act ───────────────────────────────────────────────────────────
            tool = self._tools.get(action)
            if tool is None:
                log.error("[agent] unknown action %r — stopping", action)
                return AgentResult(
                    stop_reason="unknown_action",
                    iterations=iteration,
                    total_new_events=total_new,
                    completed_actions=completed,
                )

            log.info("[agent] %s(%s)  — %s", action, target, rationale)
            try:
                result = await tool.run(target, scan_id)
            except Exception as exc:
                log.error("[agent] tool %s failed: %s", action, exc)
                result_new = 0
                summary = f"error: {exc}"
            else:
                result_new = result.new_events
                summary = result.summary

            total_new += result_new

            # ── record ────────────────────────────────────────────────────────
            completed.append(CompletedAction(
                action=action,
                target=target,
                rationale=rationale,
                new_events=result_new,
                summary=summary,
            ))

            iteration += 1
            log.info(
                "[agent] iteration %d done: %d new event(s) (total=%d)",
                iteration, result_new, total_new,
            )
