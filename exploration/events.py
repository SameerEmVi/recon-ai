"""
Exploration live-event contract (spec §14).

Typed event names + a pure `build_event` the engine uses to publish updates onto
the existing WebSocket hub. Events are NOTIFICATIONS, not the authoritative state
— the frontend recovers by fetching a snapshot and replaying from the last seq.
Kept pure so it is unit-testable and transport-independent.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Optional

# Event names (stable wire contract).
EXPLORATION_CREATED = "exploration.created"
EXPLORATION_PAUSED = "exploration.paused"
EXPLORATION_RESUMED = "exploration.resumed"
EXPLORATION_COMPLETED = "exploration.completed"
EXPLORATION_STOPPED = "exploration.stopped"

GOAL_CREATED = "goal.created"
GOAL_UPDATED = "goal.updated"
GOAL_SATISFIED = "goal.satisfied"
GOAL_BLOCKED = "goal.blocked"

INTENT_CREATED = "intent.created"
INTENT_QUEUED = "intent.queued"
INTENT_STARTED = "intent.started"
INTENT_COMPLETED = "intent.completed"
INTENT_FAILED = "intent.failed"
INTENT_REJECTED = "intent.rejected"

FACT_CREATED = "fact.created"
HINT_CREATED = "hint.created"
FINDING_LINKED = "finding.linked"

PLANNER_ROUND_STARTED = "planner.round.started"
PLANNER_ROUND_COMPLETED = "planner.round.completed"

ALL_EVENTS = frozenset({
    EXPLORATION_CREATED, EXPLORATION_PAUSED, EXPLORATION_RESUMED, EXPLORATION_COMPLETED,
    EXPLORATION_STOPPED, GOAL_CREATED, GOAL_UPDATED, GOAL_SATISFIED, GOAL_BLOCKED,
    INTENT_CREATED, INTENT_QUEUED, INTENT_STARTED, INTENT_COMPLETED, INTENT_FAILED,
    INTENT_REJECTED, FACT_CREATED, HINT_CREATED, FINDING_LINKED,
    PLANNER_ROUND_STARTED, PLANNER_ROUND_COMPLETED,
})


def build_event(event_type: str, *, exploration_id: str, scan_id: Optional[str] = None,
                node_id: Optional[str] = None, payload: Optional[dict] = None) -> dict:
    """Build a typed exploration frame for the live hub. `seq` is assigned by the
    hub on publish (like the existing live frames), not here."""
    if event_type not in ALL_EVENTS:
        raise ValueError(f"unknown exploration event: {event_type}")
    return {
        "kind": "exploration",
        "event": event_type,
        "exploration_id": exploration_id,
        "scan_id": scan_id,
        "node_id": node_id,
        "ts": datetime.now(UTC).isoformat(),
        "payload": payload or {},
    }
