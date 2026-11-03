"""
Vulnerability-intelligence assembly for the GUI.

Reads persisted findings through `FindingRepository` (no scan logic, no schema
change) and surfaces the structured, evidence-backed fields the `vulnscan`
subsystem folds into `findings.evidence` (check_id / verification status /
confidence / detection method / tier / references / remediation). Findings that
other modules emit (secret, takeover, CORS …) carry their own evidence shape —
those structured fields are simply absent and the row still renders.

Deterministic-vs-LLM split is preserved end to end: the GUI only displays what
was persisted; it never promotes a status or invents a finding.
"""

from __future__ import annotations

from collections import Counter
from uuid import UUID

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_RANK = {s: i for i, s in enumerate(_SEV_ORDER)}


def _empty() -> dict:
    return {
        "scan": None,
        "summary": {"total": 0, "by_severity": {}, "by_status": {}, "by_confidence": {}},
        "findings": [],
    }


def _row(f) -> dict:
    ev: dict = f.evidence or {}
    # Promote the well-known vulnscan keys; keep the rest (ev_* and any others) as extras.
    known = {
        "check_id", "status", "confidence", "confidence_label", "detection_method",
        "tier", "source_module", "timestamp", "url", "references", "remediation",
    }
    extra = {k: v for k, v in ev.items() if k not in known}
    conf = ev.get("confidence")
    return {
        "id": str(f.id),
        "host": f.host,
        "title": f.title,
        "description": f.description,
        "category": f.category,
        "severity": (f.severity_hint or "info").lower(),
        "status": ev.get("status"),
        "confidence": conf,
        "confidence_label": ev.get("confidence_label"),
        "detection_method": ev.get("detection_method"),
        "tier": ev.get("tier"),
        "references": ev.get("references"),
        "remediation": ev.get("remediation"),
        "url": ev.get("url"),
        "extra": extra,
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


async def build_vulns(manager, db_url: str | None, scan_id: str | None = None) -> dict:
    out = _empty()
    if not db_url:
        return out

    target = scan_id
    if not target:
        entries = manager.list()
        target = entries[0].scan_id if entries else None

    from database.repository import FindingRepository, ScanRepository
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

            sid = scan.id
            out["scan"] = {
                "scan_id": str(sid), "domain": scan.target_domain,
                "status": scan.status, "mode": scan.mode,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
            }

            findings = await FindingRepository(s).list_for_scan(sid)
            rows = [_row(f) for f in findings]
            # Strongest first: severity, then confidence.
            rows.sort(key=lambda r: (_SEV_RANK.get(r["severity"], 99),
                                     -(r["confidence"] or 0.0)))

            by_sev = Counter(r["severity"] for r in rows)
            by_status = Counter(r["status"] for r in rows if r["status"])
            by_conf = Counter(r["confidence_label"] for r in rows if r["confidence_label"])

            out["findings"] = rows
            out["summary"] = {
                "total": len(rows),
                "by_severity": {s: by_sev[s] for s in _SEV_ORDER if by_sev[s]},
                "by_status": dict(by_status),
                "by_confidence": dict(by_conf),
            }
    except Exception:
        pass
    finally:
        await engine.dispose()

    return out
