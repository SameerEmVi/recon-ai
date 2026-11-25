"""
Intent execution service (spec §7, §10).

Reads queued intents, claims one ATOMICALLY (the ExecutionClaim unique constraint
on intent_id is the guard against double execution across workers / WebSocket
reconnects / planner retries), then executes the registered tool and records the
facts it produced — re-checking scope and capability AT EXECUTION, never trusting
the planner's earlier decision.

Concurrency & recovery:
  * claim_next() inserts a claim row; a duplicate insert fails, so a second worker
    simply gets the next intent (or none).
  * heartbeat() extends the claim; recover_expired() reclaims intents whose worker
    died (claim past expiry) by deleting the stale claim and requeuing the intent.
  * releasing a claim deletes its row, so a requeued intent can be re-claimed.

The actual tool run is an injected `run_tool(intent) -> ExecutionOutcome`, so this
service is testable without real binaries and the authoritative ScopeEngine/
CapabilityPolicy/approval gate stay the gates (passed in as callables).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Awaitable, Callable, Optional

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from database.exploration_models import ExecutionClaim, Goal, Intent
from exploration.store import ExplorationStore
from exploration.types import (
    ApprovalState, EdgeRel, GOAL_TERMINAL, IntentState, NodeKind,
)


@dataclass
class FactOut:
    fact_type: str
    title: str
    asset: str = ""
    content: object = None
    confidence: float = 1.0
    source: str = ""
    source_event_id: Optional[uuid.UUID] = None
    evidence_reference: Optional[str] = None


@dataclass
class ExecutionOutcome:
    ok: bool
    summary: str = ""
    facts: list[FactOut] = field(default_factory=list)
    error: Optional[str] = None


RunTool = Callable[[Intent], Awaitable[ExecutionOutcome]]
Gate = Callable[[str], bool]

_CLAIMABLE_APPROVAL = {ApprovalState.NOT_REQUIRED.value, ApprovalState.APPROVED.value}


def _now() -> datetime:
    return datetime.now(UTC)


async def claim_next(session, exploration_id: uuid.UUID, worker: str,
                    ttl_seconds: int = 120) -> Optional[tuple[Intent, ExecutionClaim]]:
    """Atomically claim the highest-priority queued, approved intent. Returns
    (intent, claim) or None. The unique claim row is the double-execution guard."""
    candidates = (await session.execute(
        select(Intent).where(
            Intent.exploration_id == exploration_id,
            Intent.state == IntentState.QUEUED.value,
            Intent.approval_state.in_(list(_CLAIMABLE_APPROVAL)))
        .order_by(Intent.priority.asc(), Intent.created_at.asc()).limit(16))).scalars().all()

    for it in candidates:
        claim = ExecutionClaim(intent_id=it.id, exploration_id=exploration_id, worker=worker,
                               claim_token=uuid.uuid4().hex, state="claimed",
                               heartbeat_at=_now(), expires_at=_now() + timedelta(seconds=ttl_seconds))
        session.add(claim)
        try:
            await session.commit()               # INSERT — unique(intent_id) is the atomic guard
        except IntegrityError:
            await session.rollback()
            continue                             # already claimed by another worker — try next
        it.state = IntentState.RUNNING.value
        it.started_at = _now()
        await session.commit()
        await session.refresh(claim)
        return it, claim
    return None


async def heartbeat(session, claim: ExecutionClaim, ttl_seconds: int = 120) -> None:
    claim.heartbeat_at = _now()
    claim.expires_at = _now() + timedelta(seconds=ttl_seconds)
    await session.commit()


async def recover_expired(session, exploration_id: uuid.UUID) -> int:
    """Requeue intents whose worker died (claim past expiry, intent still running).
    Deletes the stale claim and resets the intent to QUEUED. Returns the count."""
    stale = (await session.execute(
        select(ExecutionClaim).where(
            ExecutionClaim.exploration_id == exploration_id,
            ExecutionClaim.state == "claimed",
            ExecutionClaim.expires_at < _now()))).scalars().all()
    n = 0
    for claim in stale:
        it = (await session.execute(select(Intent).where(Intent.id == claim.intent_id))).scalar_one_or_none()
        await session.execute(delete(ExecutionClaim).where(ExecutionClaim.id == claim.id))
        if it is not None and it.state == IntentState.RUNNING.value:
            it.state = IntentState.QUEUED.value
            it.started_at = None
            n += 1
    await session.commit()
    return n


async def _release(session, intent_id: uuid.UUID) -> None:
    await session.execute(delete(ExecutionClaim).where(ExecutionClaim.intent_id == intent_id))
    await session.commit()


async def execute_intent(session, run, intent: Intent, *, run_tool: RunTool,
                        scope_ok: Gate, capability_ok: Gate, worker: str = "executor") -> ExecutionOutcome:
    """Execute a claimed intent: re-validate, run the tool, record facts, settle
    state, release the claim. Every path releases the claim (no stuck intents)."""
    store = ExplorationStore(session)

    async def _fail(reason: str, state: str = IntentState.FAILED.value) -> ExecutionOutcome:
        intent.state = state
        intent.error = reason[:500]
        intent.completed_at = _now()
        await session.commit()
        await store.log_activity(exploration_id=run.id, activity_type="intent_failed",
                                 summary=reason, node_id=intent.id, worker=worker, tool_name=intent.tool_name)
        await _release(session, intent.id)
        return ExecutionOutcome(ok=False, error=reason)

    # Parent goal still valid?
    goal = (await session.execute(select(Goal).where(Goal.id == intent.goal_id))).scalar_one_or_none()
    if goal is None or goal.state in {g.value for g in GOAL_TERMINAL}:
        return await _fail("parent goal no longer active", IntentState.CANCELLED.value)
    # Execution-time authorization (defense in depth — never trust the planner).
    if intent.approval_state == ApprovalState.PENDING.value:
        return await _fail("awaiting operator approval", IntentState.BLOCKED.value)
    if not capability_ok(intent.tool_name):
        return await _fail(f"capability not permitted: {intent.tool_name}", IntentState.REJECTED.value)
    if intent.target and not scope_ok(intent.target):
        return await _fail(f"out of scope at execution: {intent.target}", IntentState.REJECTED.value)

    await store.log_activity(exploration_id=run.id, activity_type="intent_started",
                             summary=f"{intent.tool_name} → {intent.target}", node_id=intent.id,
                             worker=worker, tool_name=intent.tool_name)
    try:
        outcome = await run_tool(intent)
    except Exception as exc:
        return await _fail(f"tool error: {exc}")

    # Record produced facts with provenance (intent → fact YIELDS edges).
    recorded = 0
    for fo in outcome.facts:
        fact, created = await store.record_fact(
            exploration_id=run.id, fact_type=fo.fact_type, title=fo.title, goal_id=intent.goal_id,
            intent_id=intent.id, asset=fo.asset, content=fo.content, confidence=fo.confidence,
            source=fo.source or intent.tool_name, source_event_id=fo.source_event_id,
            evidence_reference=fo.evidence_reference)
        await store.add_edge(exploration_id=run.id, src_id=intent.id, src_kind=NodeKind.INTENT.value,
                             dst_id=fact.id, dst_kind=NodeKind.FACT.value, rel=EdgeRel.YIELDS.value)
        recorded += int(created)

    intent.state = IntentState.COMPLETED.value if outcome.ok else IntentState.FAILED.value
    intent.execution_summary = (outcome.summary or "")[:500]
    intent.error = outcome.error[:500] if (outcome.error and not outcome.ok) else None
    intent.completed_at = _now()
    await session.commit()
    await store.log_activity(exploration_id=run.id,
                             activity_type="intent_completed" if outcome.ok else "intent_failed",
                             summary=f"{outcome.summary} ({recorded} new fact(s))", node_id=intent.id,
                             worker=worker, tool_name=intent.tool_name)
    await _release(session, intent.id)
    return outcome
