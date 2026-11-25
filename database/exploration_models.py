"""
Persistent domain model for the autonomous exploration engine (spec §3, §12).

These are real tables — the exploration graph is no longer reconstructed from
events on every read, it is a first-class persisted goal/intent/fact tree so a
restart never erases it. They register with SQLModel.metadata (imported from
database/models.py) and are created by `init_db` like every other table.

Layering: these models store enum *values* as strings (the enum classes live in
exploration/types.py, dependency-free). Deterministic application services —
never the LLM — write to these tables.

Keyed by both `scan_job_id` (the scan) and `exploration_id` (the run), so a
scan's exploration is self-contained and indexable. Large raw tool output is NOT
stored here — facts/activities carry a reference into existing evidence storage.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Optional

from sqlalchemy import Column, Index, JSON, UniqueConstraint
from sqlmodel import Field, SQLModel


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


def _now() -> datetime:
    return datetime.now(UTC)


# ── Exploration run (root objective + container, spec §3A) ──────────────────────

class ExplorationRun(SQLModel, table=True):
    __tablename__ = "exploration_runs"
    __table_args__ = (
        UniqueConstraint("scan_job_id", name="uq_exploration_scan"),
    )

    id: uuid.UUID = Field(default_factory=_uuid, primary_key=True)
    scan_job_id: uuid.UUID = Field(foreign_key="scan_jobs.id", index=True)
    title: str
    description: str = ""
    target: str = Field(index=True)
    status: str = Field(default="created", index=True)   # ExplorationStatus
    # Operator constraints snapshot: {in_scope, out_scope, mode, max_distance,
    # intrusive, budgets:{…}}. The authoritative gate stays the ScopeEngine/policy.
    constraints: Optional[Any] = Field(default=None, sa_column=Column(JSON))
    stop_reason: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)


# ── Goal (verifiable outcome, spec §3B/§3C) ─────────────────────────────────────

class Goal(SQLModel, table=True):
    __tablename__ = "exploration_goals"
    __table_args__ = (
        Index("ix_goal_exploration_state", "exploration_id", "state"),
    )

    id: uuid.UUID = Field(default_factory=_uuid, primary_key=True)
    exploration_id: uuid.UUID = Field(foreign_key="exploration_runs.id", index=True)
    parent_goal_id: Optional[uuid.UUID] = Field(default=None, foreign_key="exploration_goals.id", index=True)
    title: str
    description: str = ""
    success_criteria: Optional[Any] = Field(default=None, sa_column=Column(JSON))  # structured criteria
    priority: int = Field(default=5)                      # 1 (highest) .. 9
    state: str = Field(default="open", index=True)        # GoalState
    completion_reason: Optional[str] = Field(default=None)
    created_by: str = Field(default="planner")            # decomposer | planner | operator
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)


# ── Intent (concrete proposed action, spec §3D) ─────────────────────────────────

class Intent(SQLModel, table=True):
    __tablename__ = "exploration_intents"
    __table_args__ = (
        Index("ix_intent_exploration_state", "exploration_id", "state"),
        # Idempotency: one open/queued intent per (goal, tool, target).
        Index("ix_intent_dedup", "exploration_id", "dedup_key"),
    )

    id: uuid.UUID = Field(default_factory=_uuid, primary_key=True)
    exploration_id: uuid.UUID = Field(foreign_key="exploration_runs.id", index=True)
    goal_id: uuid.UUID = Field(foreign_key="exploration_goals.id", index=True)
    parent_intent_id: Optional[uuid.UUID] = Field(default=None, foreign_key="exploration_intents.id")
    title: str
    description: str = ""
    tool_name: str = Field(index=True)
    target: str = Field(default="", index=True)
    rationale: str = ""
    priority: int = Field(default=5)
    required_capability: Optional[str] = Field(default=None)
    state: str = Field(default="open", index=True)        # IntentState
    approval_state: str = Field(default="not_required")   # ApprovalState
    execution_summary: Optional[str] = Field(default=None)
    error: Optional[str] = Field(default=None)
    # (tool_name:target) normalized — used to prevent duplicate proposals.
    dedup_key: str = Field(default="", index=True)
    created_at: datetime = Field(default_factory=_now)
    started_at: Optional[datetime] = Field(default=None)
    completed_at: Optional[datetime] = Field(default=None)


# ── Fact (evidence-backed observation, spec §3E) ────────────────────────────────

class Fact(SQLModel, table=True):
    __tablename__ = "exploration_facts"
    __table_args__ = (
        UniqueConstraint("exploration_id", "dedup_key", name="uq_fact_dedup"),
        Index("ix_fact_exploration_goal", "exploration_id", "goal_id"),
    )

    id: uuid.UUID = Field(default_factory=_uuid, primary_key=True)
    exploration_id: uuid.UUID = Field(foreign_key="exploration_runs.id", index=True)
    goal_id: Optional[uuid.UUID] = Field(default=None, foreign_key="exploration_goals.id", index=True)
    intent_id: Optional[uuid.UUID] = Field(default=None, foreign_key="exploration_intents.id", index=True)
    asset: str = Field(default="", index=True)            # host / target the fact concerns
    fact_type: str = Field(index=True)                    # dns_record | http_service | technology | …
    title: str
    content: Optional[Any] = Field(default=None, sa_column=Column(JSON))
    confidence: float = Field(default=1.0)                # 0..1 — NOT verification status
    source: str = Field(default="")                       # producing tool / "event" / "operator"
    source_event_id: Optional[uuid.UUID] = Field(default=None)   # provenance into events table
    evidence_reference: Optional[str] = Field(default=None)      # pointer into evidence storage
    dedup_key: str = Field(default="", index=True)
    observed_at: Optional[datetime] = Field(default=None)
    created_at: datetime = Field(default_factory=_now)


# ── Hint (non-conclusive lead, spec §3F) ────────────────────────────────────────

class Hint(SQLModel, table=True):
    __tablename__ = "exploration_hints"

    id: uuid.UUID = Field(default_factory=_uuid, primary_key=True)
    exploration_id: uuid.UUID = Field(foreign_key="exploration_runs.id", index=True)
    goal_id: Optional[uuid.UUID] = Field(default=None, foreign_key="exploration_goals.id")
    intent_id: Optional[uuid.UUID] = Field(default=None, foreign_key="exploration_intents.id")
    asset: str = Field(default="")
    title: str
    content: str = ""
    confidence: float = Field(default=0.3)
    source: str = Field(default="planner")
    created_at: datetime = Field(default_factory=_now)


# ── Activity (operation timeline, spec §3H) ─────────────────────────────────────

class Activity(SQLModel, table=True):
    __tablename__ = "exploration_activities"
    __table_args__ = (
        Index("ix_activity_exploration_ts", "exploration_id", "timestamp"),
    )

    id: uuid.UUID = Field(default_factory=_uuid, primary_key=True)
    exploration_id: uuid.UUID = Field(foreign_key="exploration_runs.id", index=True)
    node_id: Optional[uuid.UUID] = Field(default=None)    # goal/intent/fact this concerns
    worker: str = Field(default="system")
    activity_type: str = Field(index=True)                # goal_created | intent_admitted | …
    tool_name: Optional[str] = Field(default=None)
    summary: str = ""
    detail_reference: Optional[str] = Field(default=None)  # pointer to large output, not inline
    data: Optional[Any] = Field(default=None, sa_column=Column(JSON))   # small metadata only
    timestamp: datetime = Field(default_factory=_now, index=True)


# ── Edge (typed relationships, spec §8) ─────────────────────────────────────────

class ExplorationEdge(SQLModel, table=True):
    __tablename__ = "exploration_edges"
    __table_args__ = (
        UniqueConstraint("exploration_id", "src_id", "dst_id", "rel", name="uq_edge"),
        Index("ix_edge_src", "exploration_id", "src_id"),
        Index("ix_edge_dst", "exploration_id", "dst_id"),
    )

    id: uuid.UUID = Field(default_factory=_uuid, primary_key=True)
    exploration_id: uuid.UUID = Field(foreign_key="exploration_runs.id", index=True)
    src_id: uuid.UUID = Field(index=True)
    src_kind: str                                         # NodeKind
    dst_id: uuid.UUID = Field(index=True)
    dst_kind: str
    rel: str                                              # EdgeRel
    created_at: datetime = Field(default_factory=_now)


# ── PlannerRound (audit of each planning cycle, spec §5/§12) ─────────────────────

class PlannerRound(SQLModel, table=True):
    __tablename__ = "exploration_planner_rounds"
    __table_args__ = (
        Index("ix_round_exploration_no", "exploration_id", "round_no"),
    )

    id: uuid.UUID = Field(default_factory=_uuid, primary_key=True)
    exploration_id: uuid.UUID = Field(foreign_key="exploration_runs.id", index=True)
    round_no: int = Field(default=0)
    trigger: str = Field(default="")                      # what woke the planner
    status: str = Field(default="running")               # running | completed | failed | skipped
    decision_summary: Optional[str] = Field(default=None)
    operations_count: int = Field(default=0)
    started_at: datetime = Field(default_factory=_now)
    completed_at: Optional[datetime] = Field(default=None)


# ── ExecutionClaim (atomic intent claiming + recovery, spec §7) ─────────────────

class ExecutionClaim(SQLModel, table=True):
    __tablename__ = "exploration_execution_claims"
    __table_args__ = (
        # One live claim per intent — the atomicity guard against double execution.
        UniqueConstraint("intent_id", name="uq_claim_intent"),
    )

    id: uuid.UUID = Field(default_factory=_uuid, primary_key=True)
    intent_id: uuid.UUID = Field(foreign_key="exploration_intents.id", index=True)
    exploration_id: uuid.UUID = Field(foreign_key="exploration_runs.id", index=True)
    worker: str = Field(default="")
    claim_token: str = Field(default="")
    state: str = Field(default="claimed")                 # claimed | released | expired
    heartbeat_at: datetime = Field(default_factory=_now)
    expires_at: datetime = Field(default_factory=_now, index=True)
    created_at: datetime = Field(default_factory=_now)
