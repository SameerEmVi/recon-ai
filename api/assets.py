"""
Asset inventory assembly for the Asset Explorer.

Reads ONLY through the existing repositories — no new scan logic, no schema
change. Per-host rows (IPs / ports / technologies / HTTP services) come from the
aggregated `hosts` table; DNS records and the full subdomain inventory come from
the persisted event stream. Degrades gracefully with no DB (empty inventory).

A host is "live" when at least one HTTP service was observed on it (the prober
emitted an HTTP_SERVICE → a row in `Host.services`).
"""

from __future__ import annotations

from collections import Counter
from uuid import UUID

_MAX_ROWS = 5000          # per-collection cap so one huge scan can't balloon the payload


def _empty() -> dict:
    return {
        "scan": None,
        "summary": {"hosts": 0, "live_hosts": 0, "subdomains": 0, "ips": 0,
                    "open_ports": 0, "services": 0, "dns_records": 0, "technologies": 0},
        "hosts": [],
        "subdomains": [],
        "dns_records": [],
        "technologies": [],
    }


async def build_assets(manager, db_url: str | None, scan_id: str | None = None) -> dict:
    out = _empty()
    if not db_url:
        return out

    # Resolve the scan id: explicit, else newest in the session registry, else
    # newest in the DB (it may predate this server process).
    target = scan_id
    if not target:
        entries = manager.list()
        target = entries[0].scan_id if entries else None

    from database.repository import (
        EventRepository, HostRepository, ScanRepository,
    )
    from database.session import make_engine, make_session_factory
    from events.types import EventType

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

            sid = scan.id
            out["scan"] = {
                "scan_id": str(sid), "domain": scan.target_domain,
                "status": scan.status, "mode": scan.mode,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
            }

            hosts = await HostRepository(s).list_for_scan(sid)
            ev = EventRepository(s)

            ips: set = set()
            ports: set = set()
            tech: Counter = Counter()
            services_total = 0
            live = 0
            host_rows: list[dict] = []
            for h in hosts:
                h_ips = list(h.ip_addresses or [])
                h_ports = list(h.open_ports or [])
                h_tech = list(h.technologies or [])
                h_svcs = list(h.services or [])
                is_live = len(h_svcs) > 0
                if is_live:
                    live += 1
                ips.update(h_ips)
                ports.update(h_ports)
                for t in h_tech:
                    tech[t] += 1
                services_total += len(h_svcs)
                host_rows.append({
                    "hostname": h.hostname,
                    "live": is_live,
                    "ips": h_ips,
                    "ports": sorted(h_ports),
                    "technologies": h_tech,
                    "services": [
                        {"url": sv.get("url", ""), "status_code": sv.get("status_code"),
                         "title": sv.get("title")}
                        for sv in h_svcs[:50]
                    ],
                })

            # DNS records + the full subdomain inventory from the event stream.
            dns_records = [
                {"hostname": (r.data or {}).get("hostname", ""),
                 "record_type": (r.data or {}).get("record_type", ""),
                 "value": (r.data or {}).get("value", "")}
                for r in (await ev.get_by_type(sid, EventType.DNS_RECORD))[:_MAX_ROWS]
            ]
            subdomains = sorted({
                (r.data or {}).get("hostname", "")
                for r in await ev.get_by_type(sid, EventType.SUBDOMAIN)
            } - {""})[:_MAX_ROWS]

            out["hosts"] = host_rows
            out["dns_records"] = dns_records
            out["subdomains"] = subdomains
            out["technologies"] = [
                {"name": n, "count": c} for n, c in tech.most_common(50)
            ]
            out["summary"] = {
                "hosts": len(hosts),
                "live_hosts": live,
                "subdomains": len(subdomains),
                "ips": len(ips),
                "open_ports": len(ports),
                "services": services_total,
                "dns_records": len(dns_records),
                "technologies": len(tech),
            }
    except Exception:
        # A read failure must never break the explorer — return what we have.
        pass
    finally:
        await engine.dispose()

    return out
