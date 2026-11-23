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
    plan: object | None = None   # agent.plan.AgentPlan | None — the up-front plan, if any


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
        skill_library=None,   # agentskills.SkillLibrary | None (optional)
        skill_stats=None,     # agentskills.SkillStatsStore | None
        agent_role: str = "worker",
        mode_capabilities=None,  # set[str] | None — the mode's capability ceiling
        plan_first: bool = False,  # plan→execute mode: decompose the goal up front, then work the steps
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
        self._skill_library = skill_library
        self._skill_stats = skill_stats
        self._agent_role = agent_role or "worker"
        self._mode_capabilities = set(mode_capabilities or [])
        self._plan_first = plan_first

    def _inject_skills(self, state, prompt: str, scan_id) -> str:
        """Progressive disclosure: select skills relevant to the current scan
        context + this role, fold their methodology into the prompt, and record
        the load. Never raises — skill context is additive, never load-bearing."""
        if self._skill_library is None:
            return prompt
        try:
            from agentskills import context_terms, render_skill_context, select_skills

            techs, cats, titles = [], [], []
            for h in state.hosts:
                techs.extend(h.technologies or [])
                for svc in (h.services or []):
                    if svc.get("title"):
                        titles.append(svc["title"])
            for f in state.findings:
                cats.append(f.category)
            terms = context_terms(technologies=techs, categories=cats, extra_text=titles)
            selected = select_skills(
                self._skill_library.list(), role=self._agent_role,
                mode_capabilities=self._mode_capabilities, terms=terms, limit=4)
            block = render_skill_context(selected)
            if not block:
                return prompt
            if self._skill_stats is not None:
                for item in selected:
                    self._skill_stats.record_load(item["skill"].name, str(scan_id))
            log.info("[agent] loaded %d skill(s): %s", len(selected),
                     ", ".join(i["skill"].name for i in selected))
            return f"{block}\n\n---\n\n{prompt}"
        except Exception as exc:
            log.debug("[agent] skill injection skipped: %s", exc)
            return prompt

    async def _build_plan(self, state, scan_id):
        """PHASE 1 — ask the LLM once for an ordered plan, then validate it
        deterministically. The plan only *proposes* ordering: validate_steps
        drops any step whose action is not a registered tool or whose target
        was not already observed, so the plan can never widen scope or
        capabilities. Never raises — a failure yields an empty plan and the
        loop falls back to per-iteration reactive decisions."""
        from agent.plan import AgentPlan, observed_hostnames, validate_steps
        from ai.prompts.agent import AGENT_PLAN_TOOL, build_plan_prompt
        from ai.prompts.system import SYSTEM_PROMPT

        try:
            prompt = build_plan_prompt(state)
            prompt = self._inject_skills(state, prompt, scan_id)
            log.info("[agent] planning — asking LLM to decompose the objective")
            raw = await self._assessor.call(prompt, AGENT_PLAN_TOOL, system=SYSTEM_PROMPT)
        except Exception as exc:
            log.warning("[agent] planning call failed: %s — continuing without a plan", exc)
            return AgentPlan()

        if not raw:
            return AgentPlan()

        goal = str(raw.get("goal", ""))
        steps, dropped = validate_steps(
            raw.get("steps", []),
            known_actions=set(self._tools.keys()),
            observed=observed_hostnames(state.hosts),
        )
        if dropped:
            log.info("[agent] planner dropped %d proposed step(s): %s",
                     len(dropped), "; ".join(dropped[:6]))
        return AgentPlan(goal=goal, steps=steps, dropped=dropped)

    async def run(self, scan_id: UUID, target_domain: str) -> AgentResult:
        from agent.approval import AgentDecision
        from agent.plan import DONE, FAILED, SKIPPED
        from agent.state import AgentState, CompletedAction
        from agent.stopping import StopReason
        from ai.prompts.agent import AGENT_DECISION_TOOL, build_agent_prompt
        from ai.prompts.system import SYSTEM_PROMPT

        start = time.monotonic()
        completed: list[CompletedAction] = []
        total_new = 0
        iteration = 0
        plan = None   # agent.plan.AgentPlan | None — built once in plan_first mode

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
                    plan=plan,
                )

            # ── PHASE 1: plan once, up front (hosts now exist) ─────────────────
            if self._plan_first and plan is None:
                plan = await self._build_plan(state, scan_id)
                if plan.created:
                    log.info("[agent] plan (%d step(s)):\n%s", len(plan.steps), plan.render())
                else:
                    log.info("[agent] planner produced no actionable steps — "
                             "falling back to reactive decisions")

            # ── decide ─────────────────────────────────────────────────────────
            # PHASE 2: prefer the next pending plan step; once the plan is
            # exhausted (or there is no plan) fall back to a reactive LLM call,
            # so newly-discovered high-value targets are still picked up.
            step = plan.next_pending() if plan is not None else None

            if step is not None:
                decision = AgentDecision(
                    action=step.action, target=step.target, rationale=step.rationale,
                )
                log.info("[agent] plan step %d/%d: %s(%s) — %s",
                         len(plan.steps) - plan.pending_count + 1, len(plan.steps),
                         step.action, step.target, step.rationale)
            else:
                prompt = build_agent_prompt(state)
                prompt = self._inject_skills(state, prompt, scan_id)
                log.info("[agent] iteration %d — calling LLM for decision", iteration)

                raw = await self._assessor.call(
                    prompt, AGENT_DECISION_TOOL, system=SYSTEM_PROMPT,
                )

                if not raw:
                    log.warning("[agent] LLM returned empty decision — stopping")
                    return AgentResult(
                        stop_reason="llm_error",
                        iterations=iteration,
                        total_new_events=total_new,
                        completed_actions=completed,
                        plan=plan,
                    )

                decision = AgentDecision(
                    action=str(raw.get("action", "stop")),
                    target=str(raw.get("target", "")),
                    rationale=str(raw.get("rationale", "")),
                    stop_reason=str(raw.get("stop_reason", "")),
                )

                if decision.action == "stop":
                    log.info("[agent] LLM decided to stop: %s",
                             decision.stop_reason or decision.rationale)
                    return AgentResult(
                        stop_reason=StopReason.AGENT_DECIDED.value,
                        iterations=iteration,
                        total_new_events=total_new,
                        completed_actions=completed,
                        plan=plan,
                    )

            # ── approve ───────────────────────────────────────────────────────
            approved = await self._gate.check(decision)
            if not approved:
                # A rejected plan step is skipped (the plan continues); a
                # rejected reactive decision stops the loop (prior behaviour).
                if step is not None:
                    step.status = SKIPPED
                    step.summary = "rejected by approval gate"
                    log.info("[agent] plan step rejected by gate — skipping")
                    continue
                log.info("[agent] action rejected by approval gate — stopping")
                return AgentResult(
                    stop_reason="rejected_by_gate",
                    iterations=iteration,
                    total_new_events=total_new,
                    completed_actions=completed,
                    plan=plan,
                )

            # ── act ───────────────────────────────────────────────────────────
            tool = self._tools.get(decision.action)
            if tool is None:
                if step is not None:
                    step.status = SKIPPED
                    step.summary = f"unknown action: {decision.action}"
                    log.warning("[agent] plan step unknown action %r — skipping",
                                decision.action)
                    continue
                log.error("[agent] unknown action %r — stopping", decision.action)
                return AgentResult(
                    stop_reason="unknown_action",
                    iterations=iteration,
                    total_new_events=total_new,
                    completed_actions=completed,
                    plan=plan,
                )

            log.info("[agent] %s(%s)  — %s",
                     decision.action, decision.target, decision.rationale)
            try:
                result = await tool.run(decision.target, scan_id)
            except Exception as exc:
                log.error("[agent] tool %s failed: %s", decision.action, exc)
                result_new = 0
                summary = f"error: {exc}"
                if step is not None:
                    step.status = FAILED
            else:
                result_new = result.new_events
                summary = result.summary
                if step is not None:
                    step.status = DONE

            if step is not None:
                step.new_events = result_new
                step.summary = summary

            total_new += result_new

            # ── record ────────────────────────────────────────────────────────
            completed.append(CompletedAction(
                action=decision.action,
                target=decision.target,
                rationale=decision.rationale,
                new_events=result_new,
                summary=summary,
            ))

            iteration += 1
            log.info(
                "[agent] iteration %d done: %d new event(s) (total=%d)",
                iteration, result_new, total_new,
            )
