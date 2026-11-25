"""
Planner context retrieval (spec §17).

The planner must NOT receive the whole graph and all historical tool output every
round. build_context assembles a compact, bounded, structured view — the current
objective, active/incomplete goals, open intents, recent facts, hints, and the
budget snapshot — which is what the LLM reasons over. Original evidence is never
discarded; it stays in the DB and is referenced by id.
"""

from __future__ import annotations

from sqlalchemy import select

from database.exploration_models import Fact, Goal, Hint, Intent
from exploration.types import GOAL_TERMINAL, INTENT_TERMINAL


async def build_context(session, run, *, max_goals: int = 40, max_intents: int = 40,
                        max_facts: int = 60, max_hints: int = 20) -> dict:
    terminal_goals = [g.value for g in GOAL_TERMINAL]
    goals_q = await session.execute(
        select(Goal).where(Goal.exploration_id == run.id, Goal.state.notin_(terminal_goals))
        .order_by(Goal.priority.asc()).limit(max_goals))
    goals = goals_q.scalars().all()

    open_intents_q = await session.execute(
        select(Intent).where(Intent.exploration_id == run.id,
                             Intent.state.notin_([s.value for s in INTENT_TERMINAL]))
        .order_by(Intent.created_at.desc()).limit(max_intents))
    open_intents = open_intents_q.scalars().all()

    facts_q = await session.execute(
        select(Fact).where(Fact.exploration_id == run.id)
        .order_by(Fact.created_at.desc()).limit(max_facts))
    facts = list(reversed(facts_q.scalars().all()))   # oldest-first within the window

    hints_q = await session.execute(
        select(Hint).where(Hint.exploration_id == run.id)
        .order_by(Hint.created_at.desc()).limit(max_hints))
    hints = hints_q.scalars().all()

    return {
        "objective": {
            "id": str(run.id), "title": run.title, "description": run.description,
            "target": run.target, "status": run.status,
            "constraints": run.constraints or {},
        },
        "goals": [
            {"id": str(g.id), "parent_goal_id": str(g.parent_goal_id) if g.parent_goal_id else None,
             "title": g.title, "success_criteria": g.success_criteria, "state": g.state,
             "priority": g.priority}
            for g in goals
        ],
        "open_intents": [
            {"id": str(i.id), "goal_id": str(i.goal_id), "tool_name": i.tool_name,
             "target": i.target, "state": i.state, "approval_state": i.approval_state}
            for i in open_intents
        ],
        "recent_facts": [
            {"id": str(f.id), "goal_id": str(f.goal_id) if f.goal_id else None,
             "asset": f.asset, "fact_type": f.fact_type, "title": f.title, "confidence": f.confidence}
            for f in facts
        ],
        "hints": [{"id": str(h.id), "title": h.title, "asset": h.asset} for h in hints],
    }
