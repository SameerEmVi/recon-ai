"""
Shared enums for the autonomous exploration engine.

String enums so they persist as plain strings (mirroring the existing
`status: str` columns) and serialize cleanly to JSON for the API/WebSocket.
Kept dependency-free so both the DB models (database/exploration_models.py) and
the typed planner schemas (exploration/schemas.py) can import them without a
layering cycle.
"""

from __future__ import annotations

import enum


class ExplorationStatus(str, enum.Enum):
    CREATED = "created"           # root objective persisted, no goals yet
    DECOMPOSING = "decomposing"   # goal-decomposition phase running
    PLANNING = "planning"         # a planner round is in flight
    RUNNING = "running"           # intents executing / idle between rounds
    PAUSED = "paused"             # operator paused — no new rounds/intents
    COMPLETED = "completed"       # all required goals satisfied
    STOPPED = "stopped"           # operator stopped / budget / deadline
    FAILED = "failed"


class GoalState(str, enum.Enum):
    OPEN = "open"
    ACTIVE = "active"
    SATISFIED = "satisfied"
    PARTIAL = "partial"           # partially satisfied (some criteria/children met)
    BLOCKED = "blocked"
    FAILED = "failed"
    CANCELLED = "cancelled"


# Terminal goal states — no further planning needed for these.
GOAL_TERMINAL = {GoalState.SATISFIED, GoalState.FAILED, GoalState.CANCELLED}


class IntentState(str, enum.Enum):
    OPEN = "open"                 # proposed, not yet admitted to the queue
    QUEUED = "queued"             # admitted — eligible for a worker to claim
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    REJECTED = "rejected"         # deterministic validation refused it
    CANCELLED = "cancelled"


INTENT_TERMINAL = {IntentState.COMPLETED, IntentState.FAILED, IntentState.REJECTED, IntentState.CANCELLED}


class ApprovalState(str, enum.Enum):
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class NodeKind(str, enum.Enum):
    """Kinds of node the exploration graph links together."""
    OBJECTIVE = "objective"
    GOAL = "goal"
    INTENT = "intent"
    FACT = "fact"
    HINT = "hint"
    FINDING = "finding"
    DIGEST = "digest"


class EdgeRel(str, enum.Enum):
    """Typed relationships (spec §8)."""
    SPAWNS = "spawns"             # objective → goal, goal → sub-goal
    PLANS = "plans"               # goal → intent
    CHAINS = "chains"             # intent → intent, fact → fact
    YIELDS = "yields"             # intent → fact / hint
    PROVES = "proves"             # fact → finding
    ADDRESSES = "addresses"       # finding → goal


# Planner operations the LLM may emit (spec §6). The deterministic layer
# validates and applies these — the LLM never writes to the DB directly.
class PlannerOp(str, enum.Enum):
    CREATE_GOAL = "create_goal"
    UPDATE_GOAL = "update_goal"
    CREATE_INTENT = "create_intent"
    CANCEL_INTENT = "cancel_intent"
    PRIORITIZE_GOAL = "prioritize_goal"
    RECORD_HINT = "record_hint"
    REQUEST_OPERATOR_APPROVAL = "request_operator_approval"
    SATISFY_GOAL = "satisfy_goal"
    BLOCK_GOAL = "block_goal"
    CONTINUE = "continue"
    STOP = "stop"
