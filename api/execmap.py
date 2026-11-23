"""
Tool-execution mindmap assembly.

Turns a scan's persisted record into a radial "mindmap" of **what each tool did**:
the scan at the center, every tool/module that executed around it, and — per tool —
the event types it yielded (with counts). `EventRecord.source_tool` is stamped on
every event, so this is always available (no diagnostics/debug dependency). Module
job records (kind="module") enrich it with execution state, so a tool that ran but
produced nothing still appears.

Reads only through existing repositories. Degrades to an empty payload with no DB.
Pure projection — no scan logic.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from urllib.parse import urlsplit
from uuid import UUID

_MAX_EVENTS = 8000
_MAX_ETYPES_PER_TOOL = 12

# Node kinds the frontend styles by.
KINDS = ("scan", "tool", "etype")


def _host_of(data: dict) -> str:
    for k in ("hostname", "host", "address"):
        v = data.get(k)
        if v:
            return str(v)
    url = data.get("url") or data.get("found_in") or ""
    try:
        return urlsplit(url).hostname or ""
    except Exception:
        return ""


def _node(nid: str, kind: str, label: str, **attrs) -> dict:
    n = {"id": nid, "kind": kind, "label": label}
    n.update({k: v for k, v in attrs.items() if v is not None and v != ""})
    return n


def _edge(src: str, dst: str) -> dict:
    return {"id": f"{src}->{dst}", "source": src, "target": dst}


def _build(domain: str, events, jobs) -> dict:
    # Aggregate events per (tool → event-type) and distinct hosts per tool.
    by_tool_type: dict[str, Counter] = defaultdict(Counter)
    tool_hosts: dict[str, set] = defaultdict(set)
    tool_total: Counter = Counter()
    for r in events:
        tool = (r.source_tool or "unknown").strip() or "unknown"
        by_tool_type[tool][r.type] += 1
        tool_total[tool] += 1
        h = _host_of(r.data or {})
        if h:
            tool_hosts[tool].add(h)

    # Module job states (tools that ran; may have produced nothing).
    job_state: dict[str, Counter] = defaultdict(Counter)
    for j in jobs:
        if j.kind == "module" and j.module:
            job_state[j.module][j.state] += 1

    all_tools = set(tool_total) | set(job_state)

    nodes: list[dict] = [_node("scan", "scan", domain or "scan",
                               tools=len(all_tools), events=sum(tool_total.values()))]
    edges: list[dict] = []

    def roll_state(states: Counter) -> str | None:
        if not states:
            return None
        order = ["RUNNING", "VALIDATING", "QUEUED", "PAUSED", "FAILED", "CANCELLED",
                 "PARTIAL", "COMPLETED", "OK"]
        for s in order:
            if states.get(s):
                return s
        return next(iter(states))

    for tool in sorted(all_tools, key=lambda t: (-tool_total.get(t, 0), t)):
        tid = f"tool:{tool}"
        state = roll_state(job_state.get(tool, Counter()))
        nodes.append(_node(tid, "tool", tool,
                           count=tool_total.get(tool, 0),
                           hosts=len(tool_hosts.get(tool, ())),
                           state=state))
        edges.append(_edge("scan", tid))
        # Event-type children (the tool's yield), strongest first, capped.
        for etype, n in by_tool_type.get(tool, Counter()).most_common(_MAX_ETYPES_PER_TOOL):
            eid = f"{tid}:{etype}"
            nodes.append(_node(eid, "etype", f"{etype} ×{n}", etype=etype, count=n))
            edges.append(_edge(tid, eid))

    by_tool = {t: tool_total.get(t, 0) for t in sorted(all_tools)}
    summary = {
        "tools": len(all_tools),
        "events": sum(tool_total.values()),
        "event_types": len({r.type for r in events}),
        "by_tool": dict(sorted(by_tool.items(), key=lambda kv: -kv[1])),
    }
    return {"nodes": nodes, "edges": edges, "summary": summary}


async def build_execmap(manager, db_url: str | None, scan_id: str | None = None) -> dict:
    out = {"scan": None, "nodes": [], "edges": [],
           "summary": {"tools": 0, "events": 0, "event_types": 0, "by_tool": {}}}
    if not db_url:
        return out

    target = scan_id
    if not target:
        entries = manager.list()
        target = entries[0].scan_id if entries else None

    from database.repository import EventRepository, JobRepository, ScanRepository
    from database.session import make_engine, make_session_factory

    engine = make_engine(db_url)
    try:
        async with make_session_factory(engine)() as s:
            scan_repo = ScanRepository(s)
            scan = None
            if target:
                try:
                    scan = await scan_repo.get(UUID(target))
                except Exception:
                    scan = None
            if scan is None:
                recent = await scan_repo.recent_all(1)
                scan = recent[0] if recent else None
            if scan is None:
                return out

            out["scan"] = {"scan_id": str(scan.id), "domain": scan.target_domain,
                           "status": scan.status, "mode": scan.mode}
            events = await EventRepository(s).get_all(scan.id, _MAX_EVENTS)
            try:
                jobs = await JobRepository(s).list_for_scan(scan.id)
            except Exception:
                jobs = []
            built = _build(scan.target_domain, events, jobs)
            out.update(built)
    except Exception:
        pass
    finally:
        await engine.dispose()
    return out
