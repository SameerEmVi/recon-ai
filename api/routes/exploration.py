"""Exploration routes (token-gated).

Two layers, no contract break:
  * GET /api/exploration — the existing read-only event-provenance graph
    (api/exploration.build_exploration), still used by the current UI.
  * /api/exploration/... — the autonomous engine: persisted goals / intents /
    facts / activities / rounds / graph / node, plus operator actions
    (pause/resume/stop/replan, approve/reject/cancel intent, prioritize/block
    goal). These return empty/404 gracefully until an exploration exists.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from api.auth import require_token
from api.exploration import build_exploration

router = APIRouter(prefix="/api", tags=["exploration"], dependencies=[Depends(require_token)])


def _db(request: Request) -> str | None:
    return getattr(request.app.state.settings, "db_url", None)


@asynccontextmanager
async def _session(db_url: str):
    from database.session import make_engine, make_session_factory
    engine = make_engine(db_url)
    try:
        async with make_session_factory(engine)() as s:
            yield s
    finally:
        await engine.dispose()


# ── existing event-provenance graph (unchanged contract) ────────────────────────

@router.get("/exploration")
async def exploration(request: Request, scan_id: str | None = None) -> dict:
    st = request.app.state.settings
    mgr = request.app.state.scan_manager
    return await build_exploration(mgr, st.db_url, scan_id)


# ── engine reads ────────────────────────────────────────────────────────────────

@router.get("/explorations")
async def explorations(request: Request) -> dict:
    from exploration.views import list_explorations
    db = _db(request)
    if not db:
        return {"explorations": []}
    async with _session(db) as s:
        return {"explorations": await list_explorations(s)}


@router.get("/exploration/goals")
async def goals(request: Request, scan_id: str | None = None, exploration_id: str | None = None) -> dict:
    from exploration.views import list_goals, resolve_run, run_summary
    db = _db(request)
    if not db:
        return {"run": None, "goals": []}
    async with _session(db) as s:
        run = await resolve_run(s, scan_id=scan_id, exploration_id=exploration_id)
        if run is None:
            return {"run": None, "goals": []}
        return {"run": run_summary(run), "goals": await list_goals(s, run)}


@router.get("/exploration/intents")
async def intents(request: Request, scan_id: str | None = None, exploration_id: str | None = None,
                 state: str | None = None) -> dict:
    from exploration.views import list_intents, resolve_run, run_summary
    db = _db(request)
    if not db:
        return {"run": None, "intents": []}
    async with _session(db) as s:
        run = await resolve_run(s, scan_id=scan_id, exploration_id=exploration_id)
        if run is None:
            return {"run": None, "intents": []}
        return {"run": run_summary(run), "intents": await list_intents(s, run, state)}


@router.get("/exploration/facts")
async def facts(request: Request, scan_id: str | None = None, exploration_id: str | None = None,
               limit: int = 100, offset: int = 0) -> dict:
    from exploration.views import list_facts, resolve_run, run_summary
    db = _db(request)
    if not db:
        return {"run": None, "facts": [], "total": 0}
    async with _session(db) as s:
        run = await resolve_run(s, scan_id=scan_id, exploration_id=exploration_id)
        if run is None:
            return {"run": None, "facts": [], "total": 0}
        return {"run": run_summary(run), **await list_facts(s, run, limit=limit, offset=offset)}


@router.get("/exploration/activities")
async def activities(request: Request, scan_id: str | None = None, exploration_id: str | None = None,
                    limit: int = 100) -> dict:
    from exploration.views import list_activities, resolve_run, run_summary
    db = _db(request)
    if not db:
        return {"run": None, "activities": []}
    async with _session(db) as s:
        run = await resolve_run(s, scan_id=scan_id, exploration_id=exploration_id)
        if run is None:
            return {"run": None, "activities": []}
        return {"run": run_summary(run), "activities": await list_activities(s, run, limit=limit)}


@router.get("/exploration/rounds")
async def rounds(request: Request, scan_id: str | None = None, exploration_id: str | None = None) -> dict:
    from exploration.views import list_rounds, resolve_run, run_summary
    db = _db(request)
    if not db:
        return {"run": None, "rounds": []}
    async with _session(db) as s:
        run = await resolve_run(s, scan_id=scan_id, exploration_id=exploration_id)
        if run is None:
            return {"run": None, "rounds": []}
        return {"run": run_summary(run), "rounds": await list_rounds(s, run)}


@router.get("/exploration/engine-graph")
async def engine_graph(request: Request, scan_id: str | None = None, exploration_id: str | None = None) -> dict:
    from exploration.views import build_engine_graph, resolve_run
    db = _db(request)
    if not db:
        return {"run": None, "nodes": [], "edges": []}
    async with _session(db) as s:
        run = await resolve_run(s, scan_id=scan_id, exploration_id=exploration_id)
        if run is None:
            return {"run": None, "nodes": [], "edges": []}
        return await build_engine_graph(s, run)


@router.get("/exploration/node/{node_id}")
async def node(request: Request, node_id: str, scan_id: str | None = None, exploration_id: str | None = None) -> dict:
    from exploration.views import get_node, resolve_run
    db = _db(request)
    if not db:
        raise HTTPException(status_code=503, detail="no database configured")
    async with _session(db) as s:
        run = await resolve_run(s, scan_id=scan_id, exploration_id=exploration_id)
        if run is None:
            raise HTTPException(status_code=404, detail="exploration not found")
        n = await get_node(s, run, node_id)
        if n is None:
            raise HTTPException(status_code=404, detail="node not found")
        return n


# ── operator actions ─────────────────────────────────────────────────────────────

class _Reason(BaseModel):
    reason: str | None = None


class _Priority(BaseModel):
    priority: int


async def _action(request: Request, exploration_id: str, fn):
    from exploration.views import resolve_run
    db = _db(request)
    if not db:
        raise HTTPException(status_code=503, detail="no database configured")
    async with _session(db) as s:
        run = await resolve_run(s, exploration_id=exploration_id)
        if run is None:
            raise HTTPException(status_code=404, detail="exploration not found")
        return await fn(s, run)


@router.post("/exploration/{exploration_id}/pause")
async def pause_route(request: Request, exploration_id: str):
    from exploration.actions import pause
    return await _action(request, exploration_id, lambda s, r: pause(s, r))


@router.post("/exploration/{exploration_id}/resume")
async def resume_route(request: Request, exploration_id: str):
    from exploration.actions import resume
    return await _action(request, exploration_id, lambda s, r: resume(s, r))


@router.post("/exploration/{exploration_id}/stop")
async def stop_route(request: Request, exploration_id: str, body: _Reason | None = None):
    from exploration.actions import stop
    reason = (body.reason if body else None) or "operator stopped"
    return await _action(request, exploration_id, lambda s, r: stop(s, r, reason))


@router.post("/exploration/{exploration_id}/replan")
async def replan_route(request: Request, exploration_id: str):
    from exploration.actions import request_replan
    return await _action(request, exploration_id, lambda s, r: request_replan(s, r))


@router.post("/exploration/{exploration_id}/intent/{intent_id}/approve")
async def approve_route(request: Request, exploration_id: str, intent_id: str):
    from exploration.actions import approve_intent
    return await _action(request, exploration_id, lambda s, r: approve_intent(s, r, intent_id))


@router.post("/exploration/{exploration_id}/intent/{intent_id}/reject")
async def reject_route(request: Request, exploration_id: str, intent_id: str, body: _Reason | None = None):
    from exploration.actions import reject_intent
    reason = (body.reason if body else None) or "operator rejected"
    return await _action(request, exploration_id, lambda s, r: reject_intent(s, r, intent_id, reason))


@router.post("/exploration/{exploration_id}/intent/{intent_id}/cancel")
async def cancel_route(request: Request, exploration_id: str, intent_id: str):
    from exploration.actions import cancel_intent
    return await _action(request, exploration_id, lambda s, r: cancel_intent(s, r, intent_id))


@router.post("/exploration/{exploration_id}/goal/{goal_id}/prioritize")
async def prioritize_route(request: Request, exploration_id: str, goal_id: str, body: _Priority):
    from exploration.actions import prioritize_goal
    return await _action(request, exploration_id, lambda s, r: prioritize_goal(s, r, goal_id, body.priority))


@router.post("/exploration/{exploration_id}/goal/{goal_id}/block")
async def block_route(request: Request, exploration_id: str, goal_id: str, body: _Reason | None = None):
    from exploration.actions import block_goal
    reason = (body.reason if body else None) or "operator blocked"
    return await _action(request, exploration_id, lambda s, r: block_goal(s, r, goal_id, reason))
