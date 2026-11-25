"""
Typed application write-service for the exploration graph (spec §6, §8, §20).

Every mutation of the exploration domain goes through ExplorationStore — the LLM
never writes to the database, it only proposes operations that deterministic code
applies here. Dedup and provenance are enforced at this layer:

  * facts dedupe on (exploration_id, dedup_key),
  * edges dedupe on (exploration_id, src, dst, rel),
  * intents carry a normalized (tool:target) dedup_key so the same action is not
    proposed twice.

Pure persistence — no scope/capability decisions (those live in the ScopeEngine
and CapabilityPolicy and are re-checked at execution). Never raises on a benign
duplicate; it returns the existing row instead.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select

from database.exploration_models import (
    Activity, ExplorationEdge, ExplorationRun, Fact, Goal, Hint, Intent,
)
from exploration.types import ApprovalState, GoalState, IntentState


def _norm_target(t: str) -> str:
    return (t or "").strip().lower().rstrip("/")


class ExplorationStore:
    def __init__(self, session) -> None:
        self._s = session

    # ── run ─────────────────────────────────────────────────────────────────────
    async def create_run(self, *, scan_job_id: uuid.UUID, title: str, target: str,
                         description: str = "", constraints: Optional[dict] = None) -> ExplorationRun:
        run = ExplorationRun(scan_job_id=scan_job_id, title=title[:200], target=target,
                             description=description, constraints=constraints)
        self._s.add(run)
        await self._s.commit()
        await self._s.refresh(run)
        return run

    async def get_run_for_scan(self, scan_job_id: uuid.UUID) -> Optional[ExplorationRun]:
        r = await self._s.execute(select(ExplorationRun).where(ExplorationRun.scan_job_id == scan_job_id))
        return r.scalar_one_or_none()

    # ── goals ───────────────────────────────────────────────────────────────────
    async def create_goal(self, *, exploration_id: uuid.UUID, title: str, success_criteria: Any,
                          description: str = "", parent_goal_id: Optional[uuid.UUID] = None,
                          priority: int = 5, created_by: str = "planner",
                          state: str = GoalState.OPEN.value) -> Goal:
        g = Goal(exploration_id=exploration_id, title=title[:200], description=description,
                 success_criteria=success_criteria if isinstance(success_criteria, (dict, list))
                 else {"text": str(success_criteria)[:2000]},
                 parent_goal_id=parent_goal_id, priority=max(1, min(9, priority)),
                 created_by=created_by, state=state)
        self._s.add(g)
        await self._s.commit()
        await self._s.refresh(g)
        return g

    # ── intents ─────────────────────────────────────────────────────────────────
    async def create_intent(self, *, exploration_id: uuid.UUID, goal_id: uuid.UUID, title: str,
                           tool_name: str, target: str = "", description: str = "", rationale: str = "",
                           priority: int = 5, required_capability: Optional[str] = None,
                           parent_intent_id: Optional[uuid.UUID] = None,
                           state: str = IntentState.OPEN.value,
                           approval_state: str = ApprovalState.NOT_REQUIRED.value) -> Intent:
        dedup = f"{tool_name}:{_norm_target(target)}"
        it = Intent(exploration_id=exploration_id, goal_id=goal_id, title=title[:200],
                    tool_name=tool_name, target=target, description=description, rationale=rationale,
                    priority=max(1, min(9, priority)), required_capability=required_capability,
                    parent_intent_id=parent_intent_id, state=state, approval_state=approval_state,
                    dedup_key=dedup)
        self._s.add(it)
        await self._s.commit()
        await self._s.refresh(it)
        return it

    async def find_open_intent(self, exploration_id: uuid.UUID, tool_name: str, target: str) -> Optional[Intent]:
        """An existing non-terminal intent for the same (tool, target) — used by the
        planner to avoid proposing a duplicate action."""
        dedup = f"{tool_name}:{_norm_target(target)}"
        r = await self._s.execute(
            select(Intent).where(Intent.exploration_id == exploration_id, Intent.dedup_key == dedup,
                                 Intent.state.in_([IntentState.OPEN.value, IntentState.QUEUED.value,
                                                   IntentState.RUNNING.value])))
        return r.scalars().first()

    # ── facts (provenance + dedup) ───────────────────────────────────────────────
    async def record_fact(self, *, exploration_id: uuid.UUID, fact_type: str, title: str,
                          goal_id: Optional[uuid.UUID] = None, intent_id: Optional[uuid.UUID] = None,
                          asset: str = "", content: Any = None, confidence: float = 1.0,
                          source: str = "", source_event_id: Optional[uuid.UUID] = None,
                          evidence_reference: Optional[str] = None, dedup_key: Optional[str] = None,
                          observed_at: Optional[datetime] = None) -> tuple[Fact, bool]:
        """Record a fact. Returns (fact, created). Deterministic dedup on
        (exploration_id, dedup_key) — an identical observation returns the
        existing fact rather than duplicating the node."""
        key = dedup_key or f"{fact_type}:{_norm_target(asset)}:{title[:120]}"
        existing = await self._s.execute(
            select(Fact).where(Fact.exploration_id == exploration_id, Fact.dedup_key == key))
        row = existing.scalar_one_or_none()
        if row is not None:
            return row, False
        f = Fact(exploration_id=exploration_id, goal_id=goal_id, intent_id=intent_id, asset=asset,
                 fact_type=fact_type, title=title[:200],
                 content=content if isinstance(content, (dict, list)) else ({"text": str(content)[:2000]} if content is not None else None),
                 confidence=max(0.0, min(1.0, confidence)), source=source,
                 source_event_id=source_event_id, evidence_reference=evidence_reference,
                 dedup_key=key, observed_at=observed_at)
        self._s.add(f)
        await self._s.commit()
        await self._s.refresh(f)
        return f, True

    async def record_hint(self, *, exploration_id: uuid.UUID, title: str, content: str = "",
                         goal_id: Optional[uuid.UUID] = None, asset: str = "",
                         confidence: float = 0.3, source: str = "planner") -> Hint:
        h = Hint(exploration_id=exploration_id, title=title[:200], content=content[:2000],
                 goal_id=goal_id, asset=asset, confidence=max(0.0, min(1.0, confidence)), source=source)
        self._s.add(h)
        await self._s.commit()
        await self._s.refresh(h)
        return h

    # ── edges (typed, deduped) ───────────────────────────────────────────────────
    async def add_edge(self, *, exploration_id: uuid.UUID, src_id: uuid.UUID, src_kind: str,
                      dst_id: uuid.UUID, dst_kind: str, rel: str) -> Optional[ExplorationEdge]:
        existing = await self._s.execute(
            select(ExplorationEdge).where(
                ExplorationEdge.exploration_id == exploration_id, ExplorationEdge.src_id == src_id,
                ExplorationEdge.dst_id == dst_id, ExplorationEdge.rel == rel))
        if existing.scalar_one_or_none() is not None:
            return None
        e = ExplorationEdge(exploration_id=exploration_id, src_id=src_id, src_kind=src_kind,
                            dst_id=dst_id, dst_kind=dst_kind, rel=rel)
        self._s.add(e)
        await self._s.commit()
        await self._s.refresh(e)
        return e

    # ── activity timeline ─────────────────────────────────────────────────────────
    async def log_activity(self, *, exploration_id: uuid.UUID, activity_type: str, summary: str = "",
                          node_id: Optional[uuid.UUID] = None, worker: str = "system",
                          tool_name: Optional[str] = None, data: Optional[dict] = None) -> Activity:
        a = Activity(exploration_id=exploration_id, activity_type=activity_type, summary=summary[:500],
                     node_id=node_id, worker=worker, tool_name=tool_name, data=data)
        self._s.add(a)
        await self._s.commit()
        await self._s.refresh(a)
        return a
