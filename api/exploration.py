"""
Exploration-graph assembly — the live "reasoning map" of a scan.

Where the Asset Map (api/graph.py) shows *what the target is* (domain→host→ip→
service) and the Tool-Execution map (api/execmap.py) shows *what each tool did*,
the exploration graph shows *how the scan reasoned its way through the target*:
the scan's objective, the intents it pursued (each tool/module is an intent), the
facts those intents yielded, and the vulnerabilities those facts proved.

It is a pure projection of data recon-ai already persists — no new schema, no scan
logic, no LLM. The structure comes straight from event provenance:
  - `EventRecord.source_tool`      → which intent produced an event
  - `EventRecord.source_event_id`  → the parent event (⇒ intent→intent dataflow)
  - `Finding.source_event_id`      → the event (and thus the intent) that proved it

Node kinds  : start · goal · intent · fact · vulnerability
Edge rels   : spawns · intent-chain · yields · proves

Reads only through existing repositories; degrades to an empty payload with no DB.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from urllib.parse import urlsplit
from uuid import UUID

_MAX_EVENTS = 8000
_MAX_FACT_TYPES_PER_INTENT = 10   # distinct event-type facts shown per intent
_MAX_VULNS = 80                   # vulnerability nodes rendered (strongest first)

KINDS = ("start", "goal", "intent", "fact", "vulnerability")
RELS = ("spawns", "intent-chain", "yields", "proves")

# Event types that are not "facts" in their own right (handled elsewhere).
_NOT_FACT = {"finding_candidate"}

# Severity ordering for keeping the strongest vulnerabilities when capped.
_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


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


def _edge(src: str, dst: str, rel: str) -> dict:
    return {"id": f"{src}->{dst}:{rel}", "source": src, "target": dst, "rel": rel}


def _roll_state(states: Counter) -> str | None:
    """Collapse a module's job states into one representative state (running wins)."""
    if not states:
        return None
    order = ["RUNNING", "VALIDATING", "QUEUED", "PAUSED", "FAILED", "CANCELLED",
             "PARTIAL", "COMPLETED", "OK"]
    for s in order:
        if states.get(s):
            return s
    return next(iter(states))


def _build(domain: str, mode: str | None, status: str | None,
           events, findings, jobs) -> dict:
    """Pure assembly: events + findings + jobs → typed exploration graph."""
    # ── 1. index events for provenance lookups ────────────────────────────────
    event_tool: dict = {}       # event id → producing tool
    by_tool_type: dict[str, Counter] = defaultdict(Counter)
    tool_total: Counter = Counter()
    tool_hosts: dict[str, set] = defaultdict(set)
    tool_is_seed: dict[str, bool] = defaultdict(bool)   # produced a root (parentless) event

    for r in events:
        tool = (r.source_tool or "unknown").strip() or "unknown"
        event_tool[r.id] = tool
        tool_total[tool] += 1
        if (r.type or "").lower() not in _NOT_FACT:
            by_tool_type[tool][r.type] += 1
        h = _host_of(r.data or {})
        if h:
            tool_hosts[tool].add(h)
        if r.source_event_id is None:
            tool_is_seed[tool] = True

    # ── 2. intent→intent dataflow (parent tool → child tool) ──────────────────
    chain: set[tuple[str, str]] = set()
    for r in events:
        pid = r.source_event_id
        if pid is None:
            continue
        parent_tool = event_tool.get(pid)
        child_tool = event_tool.get(r.id)
        if parent_tool and child_tool and parent_tool != child_tool:
            chain.add((parent_tool, child_tool))

    # ── 3. module job states (so a running/failed intent is coloured) ─────────
    job_state: dict[str, Counter] = defaultdict(Counter)
    for j in (jobs or []):
        if getattr(j, "kind", None) == "module" and getattr(j, "module", None):
            job_state[j.module][j.state] += 1

    all_tools = set(tool_total) | set(job_state)

    nodes: list[dict] = []
    edges: list[dict] = []

    # ── 4. start + objective goal ─────────────────────────────────────────────
    nodes.append(_node("start", "start", domain or "scan",
                       mode=mode, status=status,
                       intents=len(all_tools), events=sum(tool_total.values())))
    goal_label = f"Recon & assess {domain or 'target'}"
    if mode:
        goal_label += f" ({mode})"
    nodes.append(_node("goal:objective", "goal", goal_label, mode=mode))
    edges.append(_edge("start", "goal:objective", "spawns"))

    # ── 5. intent nodes (one per tool) ────────────────────────────────────────
    targeted = {c for _, c in chain}   # tools reached via dataflow
    for tool in sorted(all_tools, key=lambda t: (-tool_total.get(t, 0), t)):
        iid = f"intent:{tool}"
        nodes.append(_node(iid, "intent", tool,
                           count=tool_total.get(tool, 0),
                           hosts=len(tool_hosts.get(tool, ())),
                           state=_roll_state(job_state.get(tool, Counter())),
                           seed=tool_is_seed.get(tool, False) or None))
        # Connect to the objective unless another intent already feeds it.
        if tool not in targeted:
            edges.append(_edge("goal:objective", iid, "spawns"))

        # Facts this intent yielded (event types with counts, strongest first).
        for etype, n in by_tool_type.get(tool, Counter()).most_common(_MAX_FACT_TYPES_PER_INTENT):
            fid = f"fact:{tool}:{etype}"
            nodes.append(_node(fid, "fact", f"{etype} ×{n}", etype=etype, count=n))
            edges.append(_edge(iid, fid, "yields"))

    # intent→intent dataflow edges.
    for a, b in sorted(chain):
        edges.append(_edge(f"intent:{a}", f"intent:{b}", "intent-chain"))

    # ── 6. vulnerabilities (findings), strongest first, capped ────────────────
    def sev_key(f):
        return _SEV_RANK.get((getattr(f, "severity_hint", None) or "").lower(), 0)

    ordered = sorted(findings or [], key=sev_key, reverse=True)
    for f in ordered[:_MAX_VULNS]:
        vid = f"vuln:{f.id}"
        nodes.append(_node(vid, "vulnerability", f.title or f.category or "finding",
                           severity=(getattr(f, "severity_hint", None) or "info"),
                           category=getattr(f, "category", None),
                           host=getattr(f, "host", None)))
        # Attribute to the intent that proved it (via the finding's source event);
        # fall back to the objective when provenance is unavailable.
        src_tool = event_tool.get(getattr(f, "source_event_id", None))
        anchor = f"intent:{src_tool}" if src_tool and src_tool in all_tools else "goal:objective"
        edges.append(_edge(anchor, vid, "proves"))

    # ── 7. prune edges whose endpoints were dropped; summarise ────────────────
    node_ids = {n["id"] for n in nodes}
    edges = [e for e in edges if e["source"] in node_ids and e["target"] in node_ids]

    by_kind: dict = {}
    for n in nodes:
        by_kind[n["kind"]] = by_kind.get(n["kind"], 0) + 1
    summary = {
        "intents": len(all_tools),
        "facts": by_kind.get("fact", 0),
        "vulnerabilities": by_kind.get("vulnerability", 0),
        "events": sum(tool_total.values()),
    }
    return {"nodes": nodes, "edges": edges, "summary": summary}


async def build_exploration(manager, db_url: str | None, scan_id: str | None = None) -> dict:
    out = {"scan": None, "nodes": [], "edges": [],
           "summary": {"intents": 0, "facts": 0, "vulnerabilities": 0, "events": 0}}
    if not db_url:
        return out

    target = scan_id
    if not target:
        entries = manager.list()
        target = entries[0].scan_id if entries else None

    from database.repository import (
        EventRepository, FindingRepository, JobRepository, ScanRepository,
    )
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
                findings = await FindingRepository(s).list_for_scan(scan.id)
            except Exception:
                findings = []
            try:
                jobs = await JobRepository(s).list_for_scan(scan.id)
            except Exception:
                jobs = []
            out.update(_build(scan.target_domain, scan.mode, scan.status,
                              events, findings, jobs))
    except Exception:
        pass
    finally:
        await engine.dispose()
    return out
