"""
Dashboard overview assembly.

Reads ONLY through the existing repositories and the in-process ScanManager —
no new scan logic, no schema change. Session-level counts come from the manager;
per-scan aggregates (assets, ports, tech, severity, recent events, job state)
come from the DB for the selected scan (the latest by default).
"""

from __future__ import annotations

from collections import Counter
from uuid import UUID


def _count_statuses(manager) -> dict:
    c = Counter(e.status for e in manager.list())
    return {
        "running": c.get("running", 0),
        "complete": c.get("complete", 0),
        "failed": c.get("failed", 0),
        "cancelled": c.get("cancelled", 0),
        "total": sum(c.values()),
    }


def _recent_session_scans(manager, limit: int = 10) -> list[dict]:
    return [
        {"scan_id": e.scan_id, "domain": e.domain, "status": e.status, "mode": e.mode,
         "created_at": e.created_at.isoformat() if e.created_at else None}
        for e in manager.list()[:limit]
    ]


def _pick_scan_id(manager, scan_id: str | None) -> str | None:
    if scan_id:
        return scan_id
    entries = manager.list()
    return entries[0].scan_id if entries else None


async def build_overview(manager, db_url: str | None, scan_id: str | None = None) -> dict:
    """Assemble the dashboard payload. Degrades gracefully: with no DB (or no
    scan yet) it returns the session-level scan counts and empty aggregates."""
    out: dict = {
        "scans": _count_statuses(manager),
        "recent_scans": _recent_session_scans(manager),
        "scan": None,
        "assets": {"subdomains": 0, "hosts": 0, "http_services": 0, "urls": 0,
                   "open_ports": 0, "findings": 0},
        "severity": {},
        "technologies": [],
        "recent_events": [],
        "jobs": {},
    }

    target = _pick_scan_id(manager, scan_id)
    # If the chosen scan isn't in the session registry, still try the DB (it may
    # predate this server process).
    if not db_url:
        return out

    from database.repository import (
        EventRepository, FindingRepository, HostRepository, JobRepository, ScanRepository,
    )
    from database.session import make_engine, make_session_factory
    from events.types import EventType

    engine = make_engine(db_url)
    try:
        async with make_session_factory(engine)() as s:
            scan_repo = ScanRepository(s)
            # Resolve the scan: explicit/most-recent-session id, else newest in DB.
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

            sid = scan.id
            out["scan"] = {
                "scan_id": str(sid), "domain": scan.target_domain, "status": scan.status,
                "mode": scan.mode, "event_count": scan.event_count,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            }

            ev = EventRepository(s)
            hosts = await HostRepository(s).list_for_scan(sid)
            findings = await FindingRepository(s).list_for_scan(sid)

            ports: set = set()
            tech: Counter = Counter()
            for h in hosts:
                for p in (h.open_ports or []):
                    ports.add(p)
                for t in (h.technologies or []):
                    tech[t] += 1

            sev: Counter = Counter()
            for f in findings:
                sev[(f.severity_hint or "info").lower()] += 1

            out["assets"] = {
                "subdomains": await ev.count_by_type(sid, EventType.SUBDOMAIN),
                "hosts": len(hosts),
                "http_services": await ev.count_by_type(sid, EventType.HTTP_SERVICE),
                "urls": await ev.count_by_type(sid, EventType.URL),
                "open_ports": len(ports),
                "findings": len(findings),
            }
            out["severity"] = dict(sev)
            out["technologies"] = [
                {"name": name, "count": n} for name, n in tech.most_common(12)
            ]
            out["recent_events"] = [
                {"type": r.type, "label": r.dedup_key, "source": r.source_tool,
                 "at": r.created_at.isoformat() if r.created_at else None}
                for r in await ev.recent(sid, 25)
            ]
            jobs = await JobRepository(s).list_for_scan(sid)
            out["jobs"] = dict(Counter(j.state for j in jobs))
    except Exception:
        # A read failure must never break the dashboard — return what we have.
        pass
    finally:
        await engine.dispose()

    return out
