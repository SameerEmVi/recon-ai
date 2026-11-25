"""
Event-driven planner (spec §5, §6).

A planner round: build compact context → ask the LLM for a PlannerDecision →
validate it (schema) → APPLY each operation deterministically. The LLM only
proposes; this module authorizes, dedupes, and persists:

  * create_goal   — skipped if a goal with the same normalized title exists
  * create_intent — rejected unless the tool is registered AND the target passes
    the injected scope check AND the mode permits its capability; deduped against
    any open intent for the same (tool, target). The planner can NEVER widen scope.
  * satisfy_goal  — recorded as a recommendation only; the deterministic
    completion engine (Phase 5) decides actual satisfaction.
  * block/prioritize/hint/cancel/continue/stop — applied as specified.

Scope/capability are injected as callables so this is testable without the full
controller, and so the authoritative ScopeEngine/CapabilityPolicy stay the gate.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Awaitable, Callable, Optional

from sqlalchemy import func, select

from database.exploration_models import Goal, Intent, PlannerRound
from exploration.context import build_context
from exploration.schemas import (
    BlockGoalOp, CancelIntentOp, ContinueOp, CreateGoalOp, CreateIntentOp,
    PlannerDecision, PrioritizeGoalOp, RecordHintOp, RequestOperatorApprovalOp,
    SatisfyGoalOp, StopOp, UpdateGoalOp,
)
from exploration.store import ExplorationStore
from exploration.types import (
    ApprovalState, EdgeRel, GoalState, IntentState, NodeKind,
)

Proposer = Callable[[str, dict], Awaitable[dict]]
ScopeOk = Callable[[str], bool]            # target → in-scope?
CapabilityOk = Callable[[str], bool]       # tool_name → permitted by mode?

# Mirror of PlannerDecision for the forced-tool call.
PLANNER_TOOL: dict = {
    "name": "plan_next",
    "description": (
        "Decide what should happen next in the exploration. Emit a reasoning "
        "summary and a list of operations (create_goal/create_intent/"
        "prioritize_goal/record_hint/satisfy_goal/block_goal/cancel_intent/"
        "request_operator_approval/continue/stop). Only propose intents on "
        "already-observed, in-scope targets; the backend validates and authorizes."
    ),
    "input_schema": {
        "type": "object",
        "required": ["operations"],
        "properties": {
            "reasoning": {"type": "string"},
            "operations": {"type": "array", "items": {"type": "object"}},
        },
    },
}


def _norm_title(t: str) -> str:
    return " ".join((t or "").lower().split())


def build_planner_prompt(context: dict, budget: Optional[dict] = None) -> str:
    import json
    budget = budget or {}
    return (
        "You are the planner for an authorized reconnaissance exploration.\n"
        "Current exploration state (compact):\n"
        f"{json.dumps(context, default=str)[:12000]}\n\n"
        f"Budget remaining: {json.dumps(budget)}\n\n"
        "Propose the next operations. Create intents only for in-scope, already-"
        "observed targets. Do not duplicate existing goals or open intents. "
        "Recommend satisfy_goal only when success criteria appear met (the backend "
        "verifies). Emit stop when all goals are satisfied or no useful work remains."
    )


class ApplyResult:
    def __init__(self) -> None:
        self.created_goals = 0
        self.created_intents = 0
        self.hints = 0
        self.rejected: list[str] = []
        self.blocked = 0
        self.satisfy_recommended: list[str] = []
        self.approvals_requested = 0
        self.stop = False
        self.stop_reason = ""

    def as_dict(self) -> dict:
        return {
            "created_goals": self.created_goals, "created_intents": self.created_intents,
            "hints": self.hints, "rejected": self.rejected, "blocked": self.blocked,
            "satisfy_recommended": self.satisfy_recommended,
            "approvals_requested": self.approvals_requested,
            "stop": self.stop, "stop_reason": self.stop_reason,
        }


async def apply_decision(store: ExplorationStore, run, decision: PlannerDecision, *,
                        scope_ok: ScopeOk, capability_ok: CapabilityOk,
                        known_tools: set[str], intrusive_tools: Optional[set[str]] = None) -> ApplyResult:
    """Apply every operation deterministically. Returns an ApplyResult summary."""
    res = ApplyResult()
    s = store._s
    intrusive_tools = intrusive_tools or set()

    # Cache existing goal titles for cheap goal dedup.
    titles = {
        _norm_title(t) for (t,) in
        (await s.execute(select(Goal.title).where(Goal.exploration_id == run.id))).all()
    }

    async def _goal(gid: str) -> Optional[Goal]:
        import uuid
        try:
            return (await s.execute(select(Goal).where(Goal.id == uuid.UUID(gid),
                                                       Goal.exploration_id == run.id))).scalar_one_or_none()
        except Exception:
            return None

    for op in decision.operations:
        if isinstance(op, CreateGoalOp):
            if _norm_title(op.title) in titles:
                continue   # idempotent — goal already exists
            import uuid
            parent = uuid.UUID(op.parent_goal_id) if op.parent_goal_id else None
            goal = await store.create_goal(exploration_id=run.id, title=op.title,
                                           success_criteria={"text": op.success_criteria},
                                           description=op.description, parent_goal_id=parent,
                                           priority=op.priority, created_by="planner",
                                           state=GoalState.OPEN.value)
            titles.add(_norm_title(op.title))
            src, kind = (parent, NodeKind.GOAL.value) if parent else (run.id, NodeKind.OBJECTIVE.value)
            await store.add_edge(exploration_id=run.id, src_id=src, src_kind=kind,
                                 dst_id=goal.id, dst_kind=NodeKind.GOAL.value, rel=EdgeRel.SPAWNS.value)
            await store.log_activity(exploration_id=run.id, activity_type="goal_created",
                                     summary=goal.title, node_id=goal.id, worker="planner")
            res.created_goals += 1

        elif isinstance(op, CreateIntentOp):
            goal = await _goal(op.goal_id)
            if goal is None:
                res.rejected.append(f"intent {op.title}: unknown goal"); continue
            if op.tool_name not in known_tools:
                await store.log_activity(exploration_id=run.id, activity_type="intent_rejected",
                                         summary=f"{op.tool_name}: tool not registered", worker="planner")
                res.rejected.append(f"{op.tool_name}: not a registered tool"); continue
            if not capability_ok(op.tool_name):
                await store.log_activity(exploration_id=run.id, activity_type="intent_rejected",
                                         summary=f"{op.tool_name}: capability forbidden by mode", worker="planner")
                res.rejected.append(f"{op.tool_name}: capability not permitted"); continue
            if op.target and not scope_ok(op.target):
                await store.log_activity(exploration_id=run.id, activity_type="intent_rejected",
                                         summary=f"{op.target}: out of scope", worker="planner",
                                         data={"tool": op.tool_name})
                res.rejected.append(f"{op.target}: out of scope"); continue
            if await store.find_open_intent(run.id, op.tool_name, op.target):
                continue   # idempotent — an open intent for this (tool,target) exists
            needs_approval = op.tool_name in intrusive_tools
            it = await store.create_intent(
                exploration_id=run.id, goal_id=goal.id, title=op.title, tool_name=op.tool_name,
                target=op.target, description=op.description, rationale=op.rationale,
                priority=op.priority, required_capability=op.required_capability,
                state=IntentState.QUEUED.value,
                approval_state=ApprovalState.PENDING.value if needs_approval else ApprovalState.NOT_REQUIRED.value)
            await store.add_edge(exploration_id=run.id, src_id=goal.id, src_kind=NodeKind.GOAL.value,
                                 dst_id=it.id, dst_kind=NodeKind.INTENT.value, rel=EdgeRel.PLANS.value)
            await store.log_activity(exploration_id=run.id, activity_type="intent_admitted",
                                     summary=f"{op.tool_name} → {op.target}", node_id=it.id,
                                     worker="planner", tool_name=op.tool_name)
            res.created_intents += 1

        elif isinstance(op, UpdateGoalOp):
            goal = await _goal(op.goal_id)
            if goal:
                if op.title: goal.title = op.title[:200]
                if op.description is not None: goal.description = op.description
                if op.success_criteria is not None: goal.success_criteria = {"text": op.success_criteria}
                if op.priority is not None: goal.priority = op.priority
                goal.updated_at = datetime.now(UTC)
                await s.commit()

        elif isinstance(op, PrioritizeGoalOp):
            goal = await _goal(op.goal_id)
            if goal:
                goal.priority = op.priority; goal.updated_at = datetime.now(UTC); await s.commit()

        elif isinstance(op, BlockGoalOp):
            goal = await _goal(op.goal_id)
            if goal:
                goal.state = GoalState.BLOCKED.value; goal.completion_reason = op.reason[:500]
                goal.updated_at = datetime.now(UTC); await s.commit()
                await store.log_activity(exploration_id=run.id, activity_type="goal_blocked",
                                         summary=op.reason, node_id=goal.id, worker="planner")
                res.blocked += 1

        elif isinstance(op, SatisfyGoalOp):
            # Recommendation only — the completion engine (Phase 5) validates evidence.
            res.satisfy_recommended.append(op.goal_id)
            await store.log_activity(exploration_id=run.id, activity_type="satisfy_recommended",
                                     summary=op.reason, worker="planner")

        elif isinstance(op, CancelIntentOp):
            import uuid
            try:
                it = (await s.execute(select(Intent).where(Intent.id == uuid.UUID(op.intent_id),
                                                           Intent.exploration_id == run.id))).scalar_one_or_none()
            except Exception:
                it = None
            if it and it.state in (IntentState.OPEN.value, IntentState.QUEUED.value):
                it.state = IntentState.CANCELLED.value; it.error = op.reason[:500]; await s.commit()

        elif isinstance(op, RecordHintOp):
            import uuid
            gid = uuid.UUID(op.goal_id) if op.goal_id else None
            await store.record_hint(exploration_id=run.id, title=op.title, content=op.content,
                                    goal_id=gid, asset=op.asset, confidence=op.confidence)
            res.hints += 1

        elif isinstance(op, RequestOperatorApprovalOp):
            import uuid
            try:
                it = (await s.execute(select(Intent).where(Intent.id == uuid.UUID(op.intent_id)))).scalar_one_or_none()
            except Exception:
                it = None
            if it:
                it.approval_state = ApprovalState.PENDING.value; await s.commit()
                res.approvals_requested += 1

        elif isinstance(op, StopOp):
            res.stop = True; res.stop_reason = op.reason

        elif isinstance(op, ContinueOp):
            pass

    return res


async def run_planner_round(session, run, propose: Proposer, *, scope_ok: ScopeOk,
                           capability_ok: CapabilityOk, known_tools: set[str],
                           trigger: str = "", budget: Optional[dict] = None,
                           intrusive_tools: Optional[set[str]] = None) -> tuple[PlannerRound, ApplyResult]:
    """One full planner round: context → propose → validate → apply → persist round."""
    store = ExplorationStore(session)
    nxt = ((await session.execute(
        select(func.count()).select_from(PlannerRound).where(PlannerRound.exploration_id == run.id))).scalar_one()) + 1
    rnd = PlannerRound(exploration_id=run.id, round_no=nxt, trigger=trigger, status="running")
    session.add(rnd); await session.commit(); await session.refresh(rnd)

    try:
        ctx = await build_context(session, run)
        prompt = build_planner_prompt(ctx, budget)
        raw = await propose(prompt, PLANNER_TOOL)
        decision = PlannerDecision.model_validate(raw or {})
        res = await apply_decision(store, run, decision, scope_ok=scope_ok, capability_ok=capability_ok,
                                   known_tools=known_tools, intrusive_tools=intrusive_tools)
        rnd.status = "completed"
        rnd.decision_summary = (decision.reasoning or "")[:500]
        rnd.operations_count = len(decision.operations)
    except Exception as exc:
        rnd.status = "failed"
        rnd.decision_summary = f"error: {exc}"[:500]
        res = ApplyResult()
    finally:
        rnd.completed_at = datetime.now(UTC)
        await session.commit()
    return rnd, res
