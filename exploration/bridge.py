"""
Scan → exploration bridge (live controller wiring).

Deterministically builds a persisted exploration from a completed scan's real
data — no LLM, no API key. Every scan automatically produces a goal-driven
exploration graph: a root objective, a default outcome-goal tree, intents
representing the recon that ran, and facts derived from the scan's actual
hosts / services / technologies / findings (with provenance). The deterministic
completion engine then evaluates the goals against that evidence.

The LLM planner (dynamic goal/intent creation) is the optional enhancement on
top — it needs a key; this bridge gives the engine real data without one.

Idempotent: a scan that already has an exploration is left untouched.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import select

from database.exploration_models import ExplorationRun
from database.models import Finding, Host
from exploration.completion import evaluate_all
from exploration.store import ExplorationStore
from exploration.types import EdgeRel, IntentState, NodeKind

# Caps keep the graph bounded on a large scan.
_MAX_SUBDOMAINS = 80
_MAX_SERVICES = 100
_MAX_TECHS = 60
_MAX_FINDINGS = 60

# The default outcome-goal tree (goals describe results, not tools).
_SUB = "Discover in-scope subdomains"
_SVC = "Identify live HTTP services"
_TECH = "Identify technologies on discovered services"
_HDR = "Collect response headers / fingerprints"
_ASSESS = "Assess services for permitted weaknesses"


async def build_from_scan(session, *, scan_job_id: uuid.UUID, target: str, mode: str = "active",
                         constraints: Optional[dict] = None) -> Optional[ExplorationRun]:
    """Build (or no-op if present) an exploration for a finished scan. Never
    raises on benign issues — returns the run, or None if nothing to build."""
    store = ExplorationStore(session)
    if await store.get_run_for_scan(scan_job_id):
        return None   # idempotent — already built

    run = await store.create_run(
        scan_job_id=scan_job_id,
        title=f"Assess the authorized attack surface of {target}",
        target=target, constraints=constraints or {"mode": mode})
    await store.log_activity(exploration_id=run.id, activity_type="exploration_created",
                             summary=f"built from scan of {target}", worker="controller")

    # Goals with STRUCTURED, deterministically-evaluable criteria.
    async def goal(title, criteria, parent=None):
        g = await store.create_goal(exploration_id=run.id, title=title, success_criteria=criteria,
                                    parent_goal_id=parent, created_by="decomposer", state="active")
        src, kind = (parent, NodeKind.GOAL.value) if parent else (run.id, NodeKind.OBJECTIVE.value)
        await store.add_edge(exploration_id=run.id, src_id=src, src_kind=kind,
                             dst_id=g.id, dst_kind=NodeKind.GOAL.value, rel=EdgeRel.SPAWNS.value)
        await store.log_activity(exploration_id=run.id, activity_type="goal_created",
                                 summary=g.title, node_id=g.id, worker="decomposer")
        return g

    g_sub = await goal(_SUB, {"kind": "min_facts", "fact_type": "subdomain", "count": 1})
    g_svc = await goal(_SVC, {"kind": "min_facts", "fact_type": "http_service", "count": 1})
    g_tech = await goal(_TECH, {"kind": "children"})
    g_hdr = await goal(_HDR, {"kind": "fact_exists", "fact_type": "technology"}, parent=g_tech.id)
    g_assess = await goal(_ASSESS, {"text": "operator confirms the assessment"})

    hosts = list((await session.execute(select(Host).where(Host.scan_job_id == scan_job_id))).scalars().all())
    findings = list((await session.execute(select(Finding).where(Finding.scan_job_id == scan_job_id))).scalars().all())

    async def intent_with_facts(goal_row, tool, facts):
        it = await store.create_intent(exploration_id=run.id, goal_id=goal_row.id,
                                       title=f"{tool} on {target}", tool_name=tool, target=target,
                                       state=IntentState.COMPLETED.value)
        it.execution_summary = f"{len(facts)} observation(s)"
        await session.commit()
        await store.add_edge(exploration_id=run.id, src_id=goal_row.id, src_kind=NodeKind.GOAL.value,
                             dst_id=it.id, dst_kind=NodeKind.INTENT.value, rel=EdgeRel.PLANS.value)
        for ftype, title, asset, content in facts:
            f, _ = await store.record_fact(exploration_id=run.id, goal_id=goal_row.id, intent_id=it.id,
                                           asset=asset, fact_type=ftype, title=title, content=content, source=tool)
            await store.add_edge(exploration_id=run.id, src_id=it.id, src_kind=NodeKind.INTENT.value,
                                 dst_id=f.id, dst_kind=NodeKind.FACT.value, rel=EdgeRel.YIELDS.value)

    sub_facts = [("subdomain", h.hostname, h.hostname, None) for h in hosts[:_MAX_SUBDOMAINS]]
    if sub_facts:
        await intent_with_facts(g_sub, "subfinder", sub_facts)

    svc_facts = [("http_service", f"{(svc or {}).get('status_code', '?')} {(svc or {}).get('url', '')}".strip(),
                  h.hostname, svc) for h in hosts for svc in (h.services or [])][:_MAX_SERVICES]
    if svc_facts:
        await intent_with_facts(g_svc, "httpx_probe", svc_facts)

    tech_facts = [("technology", t, h.hostname, None) for h in hosts for t in (h.technologies or [])][:_MAX_TECHS]
    if tech_facts:
        await intent_with_facts(g_hdr, "fingerprint", tech_facts)

    find_facts = [("finding", fi.title, fi.host, {"severity": fi.severity_hint, "category": fi.category})
                  for fi in findings[:_MAX_FINDINGS]]
    if find_facts:
        await intent_with_facts(g_assess, "vulnassess", find_facts)

    await evaluate_all(session, run)
    return run
