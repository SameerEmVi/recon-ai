"""
Deterministic goal-completion evaluator (spec §9).

A goal is satisfied ONLY when its declared success criteria are met by supporting
facts (or verified findings) — never because the LLM said so. The planner's
satisfy_goal is a recommendation; this module is the authority.

Structured success criteria (in goal.success_criteria):
  {"kind": "min_facts", "fact_type": "http_service", "count": 1}
  {"kind": "fact_exists", "fact_type": "technology"}
  {"kind": "children"}                 # all required child goals satisfied
  {"kind": "manual", "text": "..."}    # needs operator/LLM confirmation — never auto
  {"text": "..."}                      # free text (from decomposer) ⇒ treated as manual

Conservative: free-text / manual criteria are NEVER auto-satisfied (at most
`partial` when evidence exists). A parent is satisfied only when its own criteria
AND all non-cancelled children are satisfied. A previously-satisfied goal is
reopened (with an audit activity) if re-evaluation shows its criteria no longer hold.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select

from database.exploration_models import Fact, Goal
from exploration.store import ExplorationStore
from exploration.types import GoalState


@dataclass
class GoalEvaluation:
    state: str          # GoalState value the goal should hold
    reason: str
    support: int        # supporting fact count


_AUTO_KINDS = {"min_facts", "fact_exists", "children"}


def _criteria_met(criteria: dict, facts: list[Fact]) -> tuple[bool, bool, str]:
    """(met, has_partial_evidence, reason) for a goal's OWN criteria (ignoring children)."""
    kind = (criteria or {}).get("kind")
    if kind == "min_facts":
        ft = criteria.get("fact_type")
        matching = [f for f in facts if not ft or f.fact_type == ft]
        need = max(1, int(criteria.get("count", 1)))
        return len(matching) >= need, len(matching) > 0, f"{len(matching)}/{need} {ft or 'fact'}(s)"
    if kind == "fact_exists":
        ft = criteria.get("fact_type")
        matching = [f for f in facts if not ft or f.fact_type == ft]
        return len(matching) >= 1, False, f"{len(matching)} {ft or 'fact'}(s)"
    if kind == "children":
        return True, False, "gated on children"   # own criteria trivially met; children decide
    # manual / free-text — not auto-satisfiable
    return False, len(facts) > 0, "manual criteria — needs confirmation"


async def _supporting_facts(session, goal: Goal) -> list[Fact]:
    r = await session.execute(
        select(Fact).where(Fact.exploration_id == goal.exploration_id, Fact.goal_id == goal.id))
    return list(r.scalars().all())


async def _children(session, goal: Goal) -> list[Goal]:
    r = await session.execute(select(Goal).where(Goal.parent_goal_id == goal.id))
    return list(r.scalars().all())


async def evaluate_goal(session, goal: Goal) -> GoalEvaluation:
    """Deterministically evaluate one goal against its facts + children."""
    facts = await _supporting_facts(session, goal)
    children = await _children(session, goal)
    crit = goal.success_criteria or {}

    own_met, own_partial, reason = _criteria_met(crit, facts)

    active_children = [c for c in children if c.state != GoalState.CANCELLED.value]
    children_ok = all(c.state == GoalState.SATISFIED.value for c in active_children) if active_children else True
    children_partial = any(c.state in (GoalState.SATISFIED.value, GoalState.PARTIAL.value) for c in active_children)

    if own_met and children_ok:
        return GoalEvaluation(GoalState.SATISFIED.value, f"satisfied: {reason}", len(facts))
    if own_partial or children_partial or (own_met and not children_ok):
        detail = reason if own_partial else "awaiting child goals"
        return GoalEvaluation(GoalState.PARTIAL.value, f"partial: {detail}", len(facts))
    # Not satisfied and no partial evidence → stays active/open.
    return GoalEvaluation(GoalState.ACTIVE.value, f"incomplete: {reason}", len(facts))


async def apply_evaluation(session, run, goal: Goal, ev: GoalEvaluation, *, worker: str = "evaluator") -> bool:
    """Persist an evaluation. Never overrides operator-terminal states (blocked/
    failed/cancelled). Reopens a previously-satisfied goal with an audit if its
    criteria no longer hold. Returns True if the state changed."""
    store = ExplorationStore(session)
    if goal.state in (GoalState.BLOCKED.value, GoalState.FAILED.value, GoalState.CANCELLED.value):
        return False

    was = goal.state
    reopened = was == GoalState.SATISFIED.value and ev.state != GoalState.SATISFIED.value
    # Don't churn open↔active; only record meaningful transitions.
    target = ev.state
    if target == GoalState.ACTIVE.value and was in (GoalState.OPEN.value, GoalState.ACTIVE.value):
        return False
    if target == was:
        return False

    goal.state = target
    goal.completion_reason = ev.reason[:500]
    goal.updated_at = datetime.now(UTC)
    await session.commit()

    if reopened:
        await store.log_activity(exploration_id=run.id, activity_type="goal_reopened",
                                 summary=f"reopened: {ev.reason}", node_id=goal.id, worker=worker)
    elif target == GoalState.SATISFIED.value:
        await store.log_activity(exploration_id=run.id, activity_type="goal_satisfied",
                                 summary=ev.reason, node_id=goal.id, worker=worker)
    else:
        await store.log_activity(exploration_id=run.id, activity_type="goal_updated",
                                 summary=f"{was} → {target}: {ev.reason}", node_id=goal.id, worker=worker)
    return True


async def evaluate_all(session, run) -> dict:
    """Evaluate every non-cancelled goal bottom-up (children before parents, so a
    parent sees fresh child states). Returns {satisfied, partial, reopened, changed}."""
    goals = list((await session.execute(
        select(Goal).where(Goal.exploration_id == run.id,
                           Goal.state != GoalState.CANCELLED.value))).scalars().all())
    # Leaves first: a goal with no child among the set is a leaf; sort by depth desc.
    depth: dict[uuid.UUID, int] = {}
    by_id = {g.id: g for g in goals}

    def _depth(g: Goal) -> int:
        d, cur = 0, g
        seen = set()
        while cur.parent_goal_id and cur.parent_goal_id in by_id and cur.id not in seen:
            seen.add(cur.id); cur = by_id[cur.parent_goal_id]; d += 1
        return d

    for g in goals:
        depth[g.id] = _depth(g)
    goals.sort(key=lambda g: depth[g.id], reverse=True)

    out = {"satisfied": 0, "partial": 0, "reopened": 0, "changed": 0}
    for g in goals:
        was = g.state
        ev = await evaluate_goal(session, g)
        if await apply_evaluation(session, run, g, ev):
            out["changed"] += 1
            if ev.state == GoalState.SATISFIED.value:
                out["satisfied"] += 1
            elif ev.state == GoalState.PARTIAL.value:
                out["partial"] += 1
            if was == GoalState.SATISFIED.value and ev.state != GoalState.SATISFIED.value:
                out["reopened"] += 1
    return out
