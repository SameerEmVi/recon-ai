"""
Read assemblers for the exploration engine API (spec §13).

Pure projections of the persisted exploration tables — goals, intents, facts,
activities, planner rounds, a resolved node, and the goal/intent/fact graph (from
ExplorationEdge). Bounded + paginated (spec §12/§15: never an unbounded payload).
Session-based so they are unit-testable; the routes open the session.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import func, select

from database.exploration_models import (
    Activity, ExplorationEdge, ExplorationRun, Fact, Goal, Hint, Intent, PlannerRound,
)

_MAX_GRAPH_FACTS = 400


async def resolve_run(session, *, scan_id: Optional[str] = None,
                     exploration_id: Optional[str] = None) -> Optional[ExplorationRun]:
    try:
        if exploration_id:
            return (await session.execute(select(ExplorationRun).where(
                ExplorationRun.id == uuid.UUID(exploration_id)))).scalar_one_or_none()
        if scan_id:
            return (await session.execute(select(ExplorationRun).where(
                ExplorationRun.scan_job_id == uuid.UUID(scan_id)))).scalar_one_or_none()
    except Exception:
        return None
    return None


def _goal(g: Goal) -> dict:
    return {"id": str(g.id), "parent_goal_id": str(g.parent_goal_id) if g.parent_goal_id else None,
            "title": g.title, "description": g.description, "success_criteria": g.success_criteria,
            "priority": g.priority, "state": g.state, "completion_reason": g.completion_reason,
            "created_by": g.created_by,
            "created_at": g.created_at.isoformat() if g.created_at else None}


def _intent(i: Intent) -> dict:
    return {"id": str(i.id), "goal_id": str(i.goal_id), "title": i.title, "tool_name": i.tool_name,
            "target": i.target, "rationale": i.rationale, "priority": i.priority,
            "required_capability": i.required_capability, "state": i.state,
            "approval_state": i.approval_state, "execution_summary": i.execution_summary,
            "error": i.error, "created_at": i.created_at.isoformat() if i.created_at else None,
            "completed_at": i.completed_at.isoformat() if i.completed_at else None}


def _fact(f: Fact) -> dict:
    return {"id": str(f.id), "goal_id": str(f.goal_id) if f.goal_id else None,
            "intent_id": str(f.intent_id) if f.intent_id else None, "asset": f.asset,
            "fact_type": f.fact_type, "title": f.title, "content": f.content,
            "confidence": f.confidence, "source": f.source,
            "source_event_id": str(f.source_event_id) if f.source_event_id else None,
            "evidence_reference": f.evidence_reference,
            "created_at": f.created_at.isoformat() if f.created_at else None}


def _activity(a: Activity) -> dict:
    return {"id": str(a.id), "node_id": str(a.node_id) if a.node_id else None, "worker": a.worker,
            "activity_type": a.activity_type, "tool_name": a.tool_name, "summary": a.summary,
            "data": a.data, "timestamp": a.timestamp.isoformat() if a.timestamp else None}


def run_summary(run: ExplorationRun) -> dict:
    return {"id": str(run.id), "scan_id": str(run.scan_job_id), "title": run.title,
            "target": run.target, "status": run.status, "constraints": run.constraints,
            "stop_reason": run.stop_reason,
            "created_at": run.created_at.isoformat() if run.created_at else None}


async def list_goals(session, run) -> list[dict]:
    rows = (await session.execute(select(Goal).where(Goal.exploration_id == run.id)
                                  .order_by(Goal.priority.asc(), Goal.created_at.asc()))).scalars().all()
    return [_goal(g) for g in rows]


async def list_intents(session, run, state: Optional[str] = None) -> list[dict]:
    q = select(Intent).where(Intent.exploration_id == run.id)
    if state:
        q = q.where(Intent.state == state)
    rows = (await session.execute(q.order_by(Intent.created_at.desc()).limit(1000))).scalars().all()
    return [_intent(i) for i in rows]


async def list_facts(session, run, *, limit: int = 100, offset: int = 0) -> dict:
    total = (await session.execute(select(func.count()).select_from(Fact)
                                   .where(Fact.exploration_id == run.id))).scalar_one()
    rows = (await session.execute(select(Fact).where(Fact.exploration_id == run.id)
                                  .order_by(Fact.created_at.desc()).limit(min(limit, 500)).offset(offset))).scalars().all()
    return {"facts": [_fact(f) for f in rows], "total": total, "limit": limit, "offset": offset}


async def list_activities(session, run, *, limit: int = 100) -> list[dict]:
    rows = (await session.execute(select(Activity).where(Activity.exploration_id == run.id)
                                  .order_by(Activity.timestamp.desc()).limit(min(limit, 500)))).scalars().all()
    return [_activity(a) for a in rows]


async def list_rounds(session, run) -> list[dict]:
    rows = (await session.execute(select(PlannerRound).where(PlannerRound.exploration_id == run.id)
                                  .order_by(PlannerRound.round_no.desc()).limit(200))).scalars().all()
    return [{"round_no": r.round_no, "trigger": r.trigger, "status": r.status,
             "decision_summary": r.decision_summary, "operations_count": r.operations_count,
             "started_at": r.started_at.isoformat() if r.started_at else None,
             "completed_at": r.completed_at.isoformat() if r.completed_at else None} for r in rows]


async def get_node(session, run, node_id: str) -> Optional[dict]:
    try:
        nid = uuid.UUID(node_id)
    except ValueError:
        return None
    g = (await session.execute(select(Goal).where(Goal.id == nid, Goal.exploration_id == run.id))).scalar_one_or_none()
    if g:
        facts = (await session.execute(select(Fact).where(Fact.goal_id == g.id))).scalars().all()
        intents = (await session.execute(select(Intent).where(Intent.goal_id == g.id))).scalars().all()
        return {"kind": "goal", **_goal(g), "facts": [_fact(f) for f in facts],
                "intents": [_intent(i) for i in intents]}
    i = (await session.execute(select(Intent).where(Intent.id == nid, Intent.exploration_id == run.id))).scalar_one_or_none()
    if i:
        facts = (await session.execute(select(Fact).where(Fact.intent_id == i.id))).scalars().all()
        return {"kind": "intent", **_intent(i), "facts": [_fact(f) for f in facts]}
    f = (await session.execute(select(Fact).where(Fact.id == nid, Fact.exploration_id == run.id))).scalar_one_or_none()
    if f:
        return {"kind": "fact", **_fact(f)}
    return None


async def build_engine_graph(session, run) -> dict:
    """Goal/intent/fact graph from persisted nodes + edges (progressive: facts are
    capped, with a digest node when truncated)."""
    goals = (await session.execute(select(Goal).where(Goal.exploration_id == run.id))).scalars().all()
    intents = (await session.execute(select(Intent).where(Intent.exploration_id == run.id))).scalars().all()
    fact_total = (await session.execute(select(func.count()).select_from(Fact)
                                        .where(Fact.exploration_id == run.id))).scalar_one()
    facts = (await session.execute(select(Fact).where(Fact.exploration_id == run.id)
                                   .order_by(Fact.created_at.desc()).limit(_MAX_GRAPH_FACTS))).scalars().all()
    edges = (await session.execute(select(ExplorationEdge).where(ExplorationEdge.exploration_id == run.id))).scalars().all()

    nodes: list[dict] = [{"id": str(run.id), "kind": "objective", "label": run.title, "state": run.status}]
    for g in goals:
        nodes.append({"id": str(g.id), "kind": "goal", "label": g.title, "state": g.state, "priority": g.priority})
    for i in intents:
        nodes.append({"id": str(i.id), "kind": "intent", "label": f"{i.tool_name} {i.target}".strip(),
                      "state": i.state, "tool": i.tool_name})
    kept_fact_ids = {f.id for f in facts}
    for f in facts:
        nodes.append({"id": str(f.id), "kind": "fact", "label": f.title, "fact_type": f.fact_type,
                      "confidence": f.confidence})
    truncated = fact_total > len(facts)
    if truncated:
        nodes.append({"id": f"digest:{run.id}", "kind": "digest",
                      "label": f"+{fact_total - len(facts)} more facts", "count": fact_total - len(facts)})

    node_ids = {n["id"] for n in nodes}
    out_edges = []
    for e in edges:
        # Drop edges to facts beyond the render cap (keep the graph bounded).
        if e.dst_kind == "fact" and e.dst_id not in kept_fact_ids:
            continue
        s, d = str(e.src_id), str(e.dst_id)
        if s in node_ids and d in node_ids:
            out_edges.append({"id": str(e.id), "source": s, "target": d, "rel": rel_of(e)})

    by_kind: dict = {}
    for n in nodes:
        by_kind[n["kind"]] = by_kind.get(n["kind"], 0) + 1
    return {"run": run_summary(run), "nodes": nodes, "edges": out_edges,
            "summary": {"goals": len(goals), "intents": len(intents), "facts": fact_total, "by_kind": by_kind},
            "truncated": truncated}


def rel_of(e: ExplorationEdge) -> str:
    return e.rel
