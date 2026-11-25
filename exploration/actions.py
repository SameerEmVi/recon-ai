"""
Operator actions on an exploration (spec §13).

Deterministic state transitions the operator triggers from the API: pause /
resume / stop / replan, approve / reject / cancel an intent, prioritize / block a
goal. Each records an activity. Authorization of the HTTP call itself is the
route's bearer gate; these functions assume an authorized operator and only
enforce valid state machines.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Optional

from sqlalchemy import select

from database.exploration_models import Goal, Intent
from exploration.store import ExplorationStore
from exploration.types import (
    ApprovalState, ExplorationStatus, GoalState, INTENT_TERMINAL, IntentState,
)


def _now() -> datetime:
    return datetime.now(UTC)


async def set_status(session, run, status: str, *, stop_reason: Optional[str] = None,
                    activity_type: str = "exploration_status") -> dict:
    run.status = status
    if stop_reason is not None:
        run.stop_reason = stop_reason
    run.updated_at = _now()
    await session.commit()
    await ExplorationStore(session).log_activity(
        exploration_id=run.id, activity_type=activity_type, summary=f"status → {status}", worker="operator")
    return {"ok": True, "status": status}


async def pause(session, run) -> dict:
    return await set_status(session, run, ExplorationStatus.PAUSED.value, activity_type="exploration_paused")


async def resume(session, run) -> dict:
    return await set_status(session, run, ExplorationStatus.RUNNING.value, activity_type="exploration_resumed")


async def stop(session, run, reason: str = "operator stopped") -> dict:
    return await set_status(session, run, ExplorationStatus.STOPPED.value, stop_reason=reason,
                            activity_type="exploration_stopped")


async def request_replan(session, run) -> dict:
    """Record an operator replan request (the planner loop consumes it)."""
    await ExplorationStore(session).log_activity(
        exploration_id=run.id, activity_type="replan_requested", summary="operator requested replan",
        worker="operator")
    return {"ok": True}


async def _get_intent(session, run, intent_id: str) -> Optional[Intent]:
    try:
        return (await session.execute(select(Intent).where(
            Intent.id == uuid.UUID(intent_id), Intent.exploration_id == run.id))).scalar_one_or_none()
    except Exception:
        return None


async def approve_intent(session, run, intent_id: str) -> dict:
    it = await _get_intent(session, run, intent_id)
    if it is None:
        return {"ok": False, "error": "intent not found"}
    it.approval_state = ApprovalState.APPROVED.value
    await session.commit()
    await ExplorationStore(session).log_activity(exploration_id=run.id, activity_type="intent_approved",
                                                 summary=f"{it.tool_name} → {it.target}", node_id=it.id, worker="operator")
    return {"ok": True, "approval_state": it.approval_state}


async def reject_intent(session, run, intent_id: str, reason: str = "operator rejected") -> dict:
    it = await _get_intent(session, run, intent_id)
    if it is None:
        return {"ok": False, "error": "intent not found"}
    it.approval_state = ApprovalState.REJECTED.value
    it.state = IntentState.REJECTED.value
    it.error = reason[:500]
    await session.commit()
    await ExplorationStore(session).log_activity(exploration_id=run.id, activity_type="intent_rejected",
                                                 summary=reason, node_id=it.id, worker="operator")
    return {"ok": True, "state": it.state}


async def cancel_intent(session, run, intent_id: str) -> dict:
    it = await _get_intent(session, run, intent_id)
    if it is None:
        return {"ok": False, "error": "intent not found"}
    if it.state in {s.value for s in INTENT_TERMINAL}:
        return {"ok": False, "error": f"intent already {it.state}"}
    it.state = IntentState.CANCELLED.value
    await session.commit()
    await ExplorationStore(session).log_activity(exploration_id=run.id, activity_type="intent_cancelled",
                                                 summary=f"{it.tool_name} → {it.target}", node_id=it.id, worker="operator")
    return {"ok": True, "state": it.state}


async def _get_goal(session, run, goal_id: str) -> Optional[Goal]:
    try:
        return (await session.execute(select(Goal).where(
            Goal.id == uuid.UUID(goal_id), Goal.exploration_id == run.id))).scalar_one_or_none()
    except Exception:
        return None


async def prioritize_goal(session, run, goal_id: str, priority: int) -> dict:
    g = await _get_goal(session, run, goal_id)
    if g is None:
        return {"ok": False, "error": "goal not found"}
    g.priority = max(1, min(9, int(priority)))
    g.updated_at = _now()
    await session.commit()
    await ExplorationStore(session).log_activity(exploration_id=run.id, activity_type="goal_prioritized",
                                                 summary=f"priority → {g.priority}", node_id=g.id, worker="operator")
    return {"ok": True, "priority": g.priority}


async def block_goal(session, run, goal_id: str, reason: str = "operator blocked") -> dict:
    g = await _get_goal(session, run, goal_id)
    if g is None:
        return {"ok": False, "error": "goal not found"}
    g.state = GoalState.BLOCKED.value
    g.completion_reason = reason[:500]
    g.updated_at = _now()
    await session.commit()
    await ExplorationStore(session).log_activity(exploration_id=run.id, activity_type="goal_blocked",
                                                 summary=reason, node_id=g.id, worker="operator")
    return {"ok": True, "state": g.state}
