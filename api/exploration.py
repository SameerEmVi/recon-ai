"""
Exploration-graph assembly — the live "reasoning map" of a scan.

Where the Asset Map (api/graph.py) shows *what the target is* (domain→host→ip→
service) and the Tool-Execution map (api/execmap.py) shows *what each tool did*,
the exploration graph shows *how the scan works its way through the target*, as a
left-to-right plan:

    start / scope  →  goals (one per tier)  →  intents (tools)  →  facts / vulns

**Goals are recon-ai's capability tiers**, processed in order:

    1. Recon (OSINT)    — passive external intelligence, never touches the target
    2. Enumeration      — active discovery: resolve, probe, port-scan, crawl, fuzz
    3. Web app pentest  — evidence-based vulnerability checks

A tool is placed under the goal of its **tier** — `policy.tier_of_caps`, the lowest
tier whose ceiling permits its behaviour-audited capabilities — the same rule that
enforces `--mode`, so the graph can never disagree with what the mode allows. A
goal whose tier the scan's mode forbids (`policy.tier_unlocked`) is shown `locked`.

It is a pure projection of data recon-ai already persists — no new schema, no scan
logic, no LLM. Structure comes from event provenance:
  - `EventRecord.source_tool`      → which intent produced an event
  - `EventRecord.source_event_id`  → the parent event (⇒ intent→intent dataflow)
  - `Finding.source_event_id`      → the event (and thus the intent) that proved it
State comes from the per-(target, module) job rows and event timestamps.

Node kinds : start · scope · goal · intent · fact · vulnerability
Edge rels  : spawns · next · constrains · intent-chain · yields · proves

Reads only through existing repositories; degrades to an empty payload with no DB.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import UUID

_MAX_EVENTS = 8000
_MAX_FACT_TYPES_PER_INTENT = 4    # fact cards shown per intent (rest summarised)
_MAX_SAMPLES = 3                  # example values shown on a fact card
_MAX_VULNS = 80                   # vulnerability nodes rendered (strongest first)
_ACTIVE_WINDOW_S = 90             # activity this recent ⇒ the intent is "running"
_SAMPLE_LEN = 80

KINDS = ("start", "scope", "goal", "intent", "fact", "vulnerability")
RELS = ("spawns", "next", "constrains", "intent-chain", "yields", "proves")

# ── goals = the capability tiers, in processing order ──────────────────────────
# (tier, label, what it does, priority). Order is the order they are pursued.
GOALS: tuple[tuple[str, str, str, int], ...] = (
    ("osint", "Recon (OSINT)",
     "Map the attack surface from third-party sources: subdomains, historic URLs, "
     "cloud and leak intel. Never touches the target.", 9),
    ("recon", "Enumeration",
     "Resolve, probe, port-scan, fingerprint, crawl and fuzz the in-scope hosts. "
     "Discovery only, no attack payloads.", 8),
    ("pentest", "Web app pentest",
     "Evidence-based vulnerability checks on the discovered services. Intrusive "
     "tests only when explicitly authorized.", 7),
)
_TIERS = tuple(g[0] for g in GOALS)

# Wrappers that stamp the binary name rather than the module name.
_TOOL_ALIASES = {"httpx": "httpx_probe"}
_SEED_TOOLS = {"seed"}            # the controller's seed event — part of "start"

_NOT_FACT = {"FINDING_CANDIDATE"}
_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_SEV_PRIORITY = {"critical": 9, "high": 8, "medium": 6, "low": 4, "info": 2}
_DONE_STATUSES = {"complete", "completed", "failed", "cancelled"}

# Human names for event types: (singular, plural).
_ETYPE_NAMES = {
    "SUBDOMAIN": ("subdomain", "subdomains"),
    "DNS_RECORD": ("DNS record", "DNS records"),
    "IP": ("IP address", "IP addresses"),
    "OPEN_PORT": ("open port", "open ports"),
    "HTTP_SERVICE": ("HTTP service", "HTTP services"),
    "TECHNOLOGY": ("technology", "technologies"),
    "URL": ("URL", "URLs"),
    "ENDPOINT": ("endpoint", "endpoints"),
    "PARAMETER": ("parameter", "parameters"),
    "ANOMALY": ("anomaly", "anomalies"),
    "EMAIL": ("email address", "email addresses"),
}
# Which data fields make a readable example value, per event type. EMAIL is
# deliberately absent: addresses are PII, so the card shows a count only.
_SAMPLE_KEYS = {
    "SUBDOMAIN": ("hostname", "host"),
    "IP": ("address", "ip"),
    "HTTP_SERVICE": ("url", "hostname"),
    "TECHNOLOGY": ("name",),
    "URL": ("url",),
    "ENDPOINT": ("path", "url"),
    "PARAMETER": ("name",),
    "ANOMALY": ("kind", "category", "title", "description"),
}


# ── small helpers ──────────────────────────────────────────────────────────────

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


def _clip(s: str, n: int = _SAMPLE_LEN) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _sample_of(etype: str, data: dict) -> str:
    """A short, readable example value for one event (empty when none fits)."""
    if not isinstance(data, dict):
        return ""
    if etype == "OPEN_PORT":
        host, port = _host_of(data), data.get("port")
        return _clip(f"{host}:{port}" if host and port else (host or ""))
    if etype == "DNS_RECORD":
        rtype, val = data.get("record_type") or data.get("type"), data.get("value")
        return _clip(f"{rtype} {val}" if rtype and val else (val or ""))
    for k in _SAMPLE_KEYS.get(etype, ()):
        v = data.get(k)
        if v:
            if etype == "TECHNOLOGY" and data.get("version"):
                return _clip(f"{v} {data['version']}")
            return _clip(v)
    return ""


def _etype_name(etype: str, n: int) -> str:
    sing, plur = _ETYPE_NAMES.get(etype, (etype.lower().replace("_", " "),) * 2)
    return sing if n == 1 else plur


def _ts(v) -> datetime | None:
    """Normalise a DB timestamp to naive-UTC (sqlite returns naive, PG aware)."""
    if not isinstance(v, datetime):
        return None
    return v.astimezone(UTC).replace(tzinfo=None) if v.tzinfo else v


def _iso(v: datetime | None) -> str | None:
    return v.replace(tzinfo=UTC).isoformat() if v else None


def _node(nid: str, kind: str, label: str, **attrs) -> dict:
    n = {"id": nid, "kind": kind, "label": label}
    n.update({k: v for k, v in attrs.items() if v is not None and v != "" and v != []})
    return n


def _edge(src: str, dst: str, rel: str) -> dict:
    return {"id": f"{src}->{dst}:{rel}", "source": src, "target": dst, "rel": rel}


def _evidence(f) -> dict:
    ev = getattr(f, "evidence", None)
    if isinstance(ev, str):
        try:
            ev = json.loads(ev)
        except Exception:
            return {}
    return ev if isinstance(ev, dict) else {}


# ── policy: tool → tier, mode → allowed tiers ─────────────────────────────────

def _module_class(name: str):
    try:
        from modules.registry import ModuleRegistry, _registry
        ModuleRegistry.discover()
        return _registry.get(name)
    except Exception:
        return None


def _caps_of(name: str) -> frozenset[str] | None:
    """Behaviour-audited capabilities (module self-declaration > policy table)."""
    from policy.policy import MODULE_CAPABILITIES, CapabilityPolicy
    cls = _module_class(name)
    if cls is not None:
        caps = CapabilityPolicy.capabilities_of(cls)
        if caps is not None:
            return caps
    return MODULE_CAPABILITIES.get(name)


def tier_of(caps: frozenset[str] | None) -> str:
    """Which goal (tier) a tool serves — the policy's own tier rule (the lowest
    tier whose ceiling permits it), so the graph and enforcement share one rule."""
    from policy import tier_of_caps
    return tier_of_caps(caps) or "recon"   # unclassified (never runs): show as discovery


def _tiers_allowed(mode: str | None) -> set[str]:
    """Tiers the scan's mode unlocks (a forbidden tier renders `locked`)."""
    from policy import tier_unlocked
    return {t for t in _TIERS if tier_unlocked(mode, t)}


def _is_seed_module(name: str) -> bool:
    """A seed module watches no events: it runs once, at scan start."""
    cls = _module_class(name)
    return cls is not None and not getattr(cls, "watched_events", None)


def _value_of(name: str) -> int:
    """The planner's expected-value score for a tool, as an ARTEX-style P0–P9."""
    cls = _module_class(name)
    v = getattr(cls, "expected_value", None) if cls is not None else None
    try:
        return max(0, min(9, int(v))) if v is not None else 3
    except (TypeError, ValueError):
        return 3


# ── state derivation ──────────────────────────────────────────────────────────

def _intent_state(*, scan_done: bool, ran: bool, failed: bool,
                  last: datetime | None, now: datetime) -> str:
    """pending · running · waiting · done · failed · skipped.

    Module job rows stay RUNNING from first dispatch until scan end (reactive
    modules can fire again any time), so mid-scan "running" means *recent
    activity*; an intent that has run but gone quiet is "waiting" for input."""
    if scan_done:
        if failed:
            return "failed"
        return "done" if ran else "skipped"
    if not ran:
        return "pending"
    if last is not None and (now - last).total_seconds() <= _ACTIVE_WINDOW_S:
        return "running"
    return "failed" if failed else "waiting"


def _goal_state(*, allowed: bool, scan_done: bool, states: list[str]) -> str:
    """locked · pending · running · waiting · achieved · incomplete · skipped."""
    if not allowed:
        return "locked"
    ran = [s for s in states if s not in ("pending", "skipped")]
    if scan_done:
        if not ran:
            return "skipped"
        return "incomplete" if "failed" in states else "achieved"
    if "running" in states:
        return "running"
    return "waiting" if ran else "pending"


# ── pure assembly ─────────────────────────────────────────────────────────────

def _build(domain: str, mode: str | None, status: str | None,
           events, findings, jobs, *, scope: dict | None = None,
           planned: list[str] | None = None, now: datetime | None = None,
           started: datetime | None = None) -> dict:
    """events + findings + jobs (+ live planned modules) → typed exploration graph."""
    now = _ts(now) or datetime.now(UTC).replace(tzinfo=None)
    started = _ts(started)
    scan_done = (status or "").lower() in _DONE_STATUSES

    # ── 1. index events ───────────────────────────────────────────────────────
    event_tool: dict = {}
    tool_total: Counter = Counter()
    tool_hosts: dict[str, set] = defaultdict(set)
    tool_first: dict[str, datetime] = {}
    tool_last: dict[str, datetime] = {}
    tool_is_seed: dict[str, bool] = defaultdict(bool)
    by_tool_type: dict[str, Counter] = defaultdict(Counter)
    samples: dict[tuple[str, str], list[str]] = defaultdict(list)

    def touch(tool: str, t: datetime | None) -> None:
        if t is None:
            return
        if tool not in tool_first or t < tool_first[tool]:
            tool_first[tool] = t
        if tool not in tool_last or t > tool_last[tool]:
            tool_last[tool] = t

    for r in events:
        raw = (getattr(r, "source_tool", None) or "unknown").strip() or "unknown"
        tool = _TOOL_ALIASES.get(raw, raw)
        event_tool[r.id] = tool
        if tool in _SEED_TOOLS:
            continue
        tool_total[tool] += 1
        etype = (getattr(r, "type", "") or "").upper()
        data = getattr(r, "data", None) or {}
        if etype not in _NOT_FACT:
            by_tool_type[tool][etype] += 1
            bucket = samples[(tool, etype)]
            if len(bucket) < _MAX_SAMPLES:
                s = _sample_of(etype, data)
                if s and s not in bucket:
                    bucket.append(s)
        h = _host_of(data) if isinstance(data, dict) else ""
        if h:
            tool_hosts[tool].add(h)
        if getattr(r, "source_event_id", None) is None:
            tool_is_seed[tool] = True
        touch(tool, _ts(getattr(r, "created_at", None)))

    # ── 2. intent→intent dataflow (parent tool → child tool) ──────────────────
    chain: set[tuple[str, str]] = set()
    for r in events:
        pid = getattr(r, "source_event_id", None)
        if pid is None:
            continue
        a, b = event_tool.get(pid), event_tool.get(r.id)
        if a and b and a != b and a not in _SEED_TOOLS and b not in _SEED_TOOLS:
            chain.add((a, b))
    fed_by: dict[str, set] = defaultdict(set)
    feeds: dict[str, set] = defaultdict(set)
    for a, b in chain:
        feeds[a].add(b)
        fed_by[b].add(a)

    # ── 3. module job rows (per target × module) ──────────────────────────────
    job_states: dict[str, Counter] = defaultdict(Counter)
    for j in (jobs or []):
        if getattr(j, "kind", None) != "module" or not getattr(j, "module", None):
            continue
        job_states[j.module][(getattr(j, "state", "") or "").upper()] += 1
        touch(j.module, _ts(getattr(j, "created_at", None)))
        touch(j.module, _ts(getattr(j, "updated_at", None)))

    all_tools = (set(tool_total) | set(job_states) | set(planned or ())) - _SEED_TOOLS

    # ── 4. intents: tier, state, ordering ─────────────────────────────────────
    allowed = _tiers_allowed(mode)
    intents_by_tier: dict[str, list[dict]] = defaultdict(list)
    intent_ids: set[str] = set()
    for tool in all_tools:
        caps = _caps_of(tool)
        tier = tier_of(caps)
        count = tool_total.get(tool, 0)
        ran = count > 0 or bool(job_states.get(tool))
        if not ran and tool in (planned or ()) and _is_seed_module(tool):
            # Seed modules all launch at scan start and leave no job row, so one
            # that has found nothing yet has still run (it isn't "queued").
            ran = True
            touch(tool, started)
        js = job_states.get(tool, Counter())
        state = _intent_state(scan_done=scan_done, ran=ran, failed=js.get("FAILED", 0) > 0,
                              last=tool_last.get(tool), now=now)
        hosts = len(tool_hosts.get(tool, ()))
        if count:
            summary = f"{count} event{'s' if count != 1 else ''}" + (
                f" across {hosts} host{'s' if hosts != 1 else ''}" if hosts else "")
        else:
            summary = {
                "pending": "Queued, waiting for input",
                "running": "Running",
                "waiting": "Started, nothing found yet",
                "done": "Ran, nothing found",
                "failed": "Failed",
                "skipped": "Never triggered",
            }.get(state, "")
        types = by_tool_type.get(tool, Counter())
        intents_by_tier[tier].append({
            "tool": tool, "tier": tier, "caps": sorted(caps or ()), "count": count,
            "hosts": hosts, "state": state, "summary": summary,
            "first": tool_first.get(tool), "last": tool_last.get(tool),
            "seed": tool_is_seed.get(tool, False), "types": types,
            "failed_jobs": js.get("FAILED", 0),
        })
        intent_ids.add(f"intent:{tool}")

    nodes: list[dict] = []
    edges: list[dict] = []

    # ── 5. start + scope ──────────────────────────────────────────────────────
    total_events = sum(tool_total.values())
    nodes.append(_node("start", "start", domain or "scan",
                       summary=f"Authorized target · {mode or 'default'} mode",
                       mode=mode, status=status, intents=len(all_tools),
                       events=total_events))
    if scope:
        ins = [str(s) for s in (scope.get("in_scope") or [])]
        outs = [str(s) for s in (scope.get("out_scope") or [])]
        parts = [f"In: {', '.join(ins) or '—'}", f"Out: {', '.join(outs) or 'none'}"]
        if scope.get("max_distance") is not None:
            parts.append(f"max distance {scope['max_distance']}")
        nodes.append(_node("scope", "scope", "Scope", summary=" · ".join(parts),
                           in_scope=ins, out_scope=outs,
                           max_distance=scope.get("max_distance")))

    # ── 6. goals (tiers) → intents → facts ────────────────────────────────────
    goal_states: dict[str, str] = {}
    for step, (tier, label, desc, prio) in enumerate(GOALS, start=1):
        gid = f"goal:{tier}"
        items = intents_by_tier.get(tier, [])
        # Process order: by first activity (chronological), queued ones last.
        items.sort(key=lambda i: (i["first"] is None, i["first"] or now, i["tool"]))
        gstate = _goal_state(allowed=tier in allowed, scan_done=scan_done,
                             states=[i["state"] for i in items])
        goal_states[tier] = gstate
        g_events = sum(i["count"] for i in items)
        nodes.append(_node(gid, "goal", label, summary=desc, tier=tier, step=step,
                           priority=prio, state=gstate, intents=len(items),
                           events=g_events,
                           done=sum(1 for i in items if i["state"] in ("done", "waiting")),
                           reason=(f"Not allowed in '{mode}' mode" if tier not in allowed
                                   else None)))
        edges.append(_edge("start", gid, "spawns"))
        if scope and tier in allowed:
            edges.append(_edge("scope", gid, "constrains"))

        for order, it in enumerate(items):
            iid = f"intent:{it['tool']}"
            types: Counter = it["types"]
            shown = types.most_common(_MAX_FACT_TYPES_PER_INTENT)
            nodes.append(_node(
                iid, "intent", it["tool"], summary=it["summary"], tier=tier,
                state=it["state"], priority=_value_of(it["tool"]), order=order,
                count=it["count"], hosts=it["hosts"], caps=it["caps"],
                seed=it["seed"] or None, first_seen=_iso(it["first"]),
                last_seen=_iso(it["last"]), failed_jobs=it["failed_jobs"] or None,
                fed_by=sorted(fed_by.get(it["tool"], ())),
                feeds=sorted(feeds.get(it["tool"], ())),
                more_facts=max(0, len(types) - len(shown)) or None))
            edges.append(_edge(gid, iid, "spawns"))
            for etype, n in shown:
                fid = f"fact:{it['tool']}:{etype}"
                ex = samples.get((it["tool"], etype), [])
                nodes.append(_node(fid, "fact", f"{n} {_etype_name(etype, n)}",
                                   summary=", ".join(ex) + ("…" if n > len(ex) and ex else ""),
                                   etype=etype, count=n, samples=ex))
                edges.append(_edge(iid, fid, "yields"))

    # Goals are pursued one after another: OSINT → Enumeration → Pentest.
    for (a, *_), (b, *_) in zip(GOALS, GOALS[1:]):
        edges.append(_edge(f"goal:{a}", f"goal:{b}", "next"))

    # Dataflow between intents (rendered on demand by the UI).
    for a, b in sorted(chain):
        if f"intent:{a}" in intent_ids and f"intent:{b}" in intent_ids:
            edges.append(_edge(f"intent:{a}", f"intent:{b}", "intent-chain"))

    # ── 7. vulnerabilities, strongest first, capped ───────────────────────────
    def sev_key(f):
        return _SEV_RANK.get((getattr(f, "severity_hint", None) or "").lower(), 0)

    for f in sorted(findings or [], key=sev_key, reverse=True)[:_MAX_VULNS]:
        vid = f"vuln:{f.id}"
        sev = (getattr(f, "severity_hint", None) or "info").lower()
        ev = _evidence(f)
        nodes.append(_node(vid, "vulnerability", f.title or f.category or "finding",
                           summary=getattr(f, "host", None), severity=sev,
                           priority=_SEV_PRIORITY.get(sev, 2),
                           category=getattr(f, "category", None),
                           host=getattr(f, "host", None),
                           verification=ev.get("status"),
                           confidence=ev.get("confidence")))
        # Attribute to the intent that proved it; else to the pentest goal.
        src_tool = event_tool.get(getattr(f, "source_event_id", None))
        anchor = f"intent:{src_tool}" if f"intent:{src_tool}" in intent_ids else "goal:pentest"
        edges.append(_edge(anchor, vid, "proves"))

    # ── 8. prune dangling edges; summarise ────────────────────────────────────
    node_ids = {n["id"] for n in nodes}
    edges = [e for e in edges if e["source"] in node_ids and e["target"] in node_ids]
    by_kind = Counter(n["kind"] for n in nodes)
    summary = {
        "goals": len(GOALS),
        "goals_achieved": sum(1 for s in goal_states.values() if s == "achieved"),
        "intents": len(all_tools),
        "facts": by_kind.get("fact", 0),
        "vulnerabilities": by_kind.get("vulnerability", 0),
        "events": total_events,
    }
    return {"nodes": nodes, "edges": edges, "summary": summary}


def _planned_modules(manager, scan_id: str) -> list[str] | None:
    """Modules loaded for a scan still held in memory (GUI-launched), so queued
    intents show before they fire. Read-only; None when unavailable."""
    try:
        entry = manager.get(scan_id) if manager is not None else None
        ctrl = getattr(entry, "controller", None)
        mods = getattr(ctrl, "_loaded_modules", None) or []
        names = [getattr(m, "name", None) for m in mods]
        return [n for n in names if isinstance(n, str) and n] or None
    except Exception:
        return None


async def build_exploration(manager, db_url: str | None, scan_id: str | None = None) -> dict:
    out = {"scan": None, "nodes": [], "edges": [],
           "summary": {"goals": 0, "goals_achieved": 0, "intents": 0, "facts": 0,
                       "vulnerabilities": 0, "events": 0}}
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
            scope = scan.scope_config if isinstance(scan.scope_config, dict) else None
            if scope is None and isinstance(scan.scope_config, str):
                try:
                    scope = json.loads(scan.scope_config)
                except Exception:
                    scope = None
            out.update(_build(scan.target_domain, scan.mode, scan.status,
                              events, findings, jobs, scope=scope,
                              planned=_planned_modules(manager, str(scan.id)),
                              started=getattr(scan, "created_at", None)))
    except Exception:
        pass
    finally:
        await engine.dispose()
    return out
