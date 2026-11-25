"""
Cross-task Findings assembly + triage mutations for the GUI.

This is the operator-facing, **cross-scan** vulnerability overview (vs `api/vulns.py`,
which is one scan's view). It joins the deterministic `Finding` rows every scan
persisted with a thin, operator-owned `FindingTriage` row (report stage + note +
optional verification override). The split is deliberate and mirrors
deterministic-vs-LLM: the engine owns the finding and its detected status; the
human owns the submission workflow and can confirm/downgrade without the engine
ever promoting anything.

Reads/writes through the existing repositories + one new small table. Degrades to
an empty payload with no DB. The triage table is created on demand (idempotent),
so the web app works against a DB that predates this feature.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from uuid import UUID

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_RANK = {s: i for i, s in enumerate(_SEV_ORDER)}
_STAGES = ["pending", "triaged", "submitted", "accepted", "rejected", "duplicate", "informative"]

# db_urls whose triage table we've already ensured this process.
_ensured: set[str] = set()


async def _ensure_triage(engine, db_url: str) -> None:
    if db_url in _ensured:
        return
    from database.models import FindingTriage
    try:
        async with engine.begin() as conn:
            await conn.run_sync(lambda c: FindingTriage.__table__.create(c, checkfirst=True))
        _ensured.add(db_url)
    except Exception:
        # Never block a read on schema setup — a read just sees no triage rows.
        pass


def _row(f, scan, triage) -> dict:
    ev: dict = f.evidence or {}
    detected = ev.get("status")                       # vulnscan: OBSERVED/POTENTIAL/…
    stage = triage.report_stage if triage else "pending"
    override = triage.verification_override if triage else None
    return {
        "id": str(f.id),
        "host": f.host,
        "title": f.title,
        "description": f.description,
        "category": f.category,
        "severity": (f.severity_hint or "info").lower(),
        "detected_status": detected,
        "status": override or detected,               # effective verification status
        "verification_override": override,
        "report_stage": stage,
        "note": triage.note if triage else None,
        "confidence": ev.get("confidence"),
        "confidence_label": ev.get("confidence_label"),
        "detection_method": ev.get("detection_method"),
        "tier": ev.get("tier"),
        "references": ev.get("references"),
        "remediation": ev.get("remediation"),
        "url": ev.get("url"),
        "check_id": ev.get("check_id"),
        "task": {
            "scan_id": str(f.scan_job_id),
            "domain": scan.target_domain if scan else "",
            "mode": scan.mode if scan else None,
        },
        "created_at": f.created_at.isoformat() if f.created_at else None,
        "triaged_at": triage.updated_at.isoformat() if (triage and triage.updated_at) else None,
    }


async def _load(db_url: str):
    """Return (finding_rows, scans_by_id, triage_by_id) across ALL scans."""
    from sqlalchemy import select

    from database.models import Finding, FindingTriage
    from database.repository import ScanRepository
    from database.session import make_engine, make_session_factory

    engine = make_engine(db_url)
    try:
        await _ensure_triage(engine, db_url)
        async with make_session_factory(engine)() as s:
            findings = (await s.execute(
                select(Finding).order_by(Finding.created_at.desc()).limit(10_000)
            )).scalars().all()
            scans = {sc.id: sc for sc in await ScanRepository(s).recent_all(2000)}
            triage = {t.finding_id: t for t in
                      (await s.execute(select(FindingTriage))).scalars().all()}
            return findings, scans, triage
    finally:
        await engine.dispose()


def _apply_filters(rows: list[dict], *, scan_id, severity, report_stage, status,
                   category, host, q) -> list[dict]:
    sev = (severity or "").lower()
    stage = (report_stage or "").lower()
    st = (status or "").lower()
    cat = (category or "").lower()
    host_n = (host or "").lower()
    q_n = (q or "").strip().lower()

    def keep(r: dict) -> bool:
        if scan_id and r["task"]["scan_id"] != scan_id:
            return False
        if sev and r["severity"] != sev:
            return False
        if stage and r["report_stage"] != stage:
            return False
        if st and (r["status"] or "").lower() != st:
            return False
        if cat and r["category"].lower() != cat:
            return False
        if host_n and host_n not in (r["host"] or "").lower():
            return False
        if q_n and q_n not in (
            f"{r['title']} {r['host']} {r['category']} {r['description']}".lower()
        ):
            return False
        return True

    return [r for r in rows if keep(r)]


def _conf(r: dict) -> float:
    """Confidence as a float for sorting. Evidence JSON may store it as a string
    (or omit it), so coerce defensively — a bad value sorts as 0.0, never raises."""
    try:
        return float(r.get("confidence") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _sort(rows: list[dict], sort: str) -> list[dict]:
    if sort == "time":
        return sorted(rows, key=lambda r: r["created_at"] or "", reverse=True)
    if sort == "stage":
        order = {s: i for i, s in enumerate(_STAGES)}
        return sorted(rows, key=lambda r: order.get(r["report_stage"], 99))
    # default: severity then confidence
    return sorted(rows, key=lambda r: (_SEV_RANK.get(r["severity"], 99), -_conf(r)))


async def build_findings(db_url: str | None, *, scan_id: str | None = None,
                         severity: str | None = None, report_stage: str | None = None,
                         status: str | None = None, category: str | None = None,
                         host: str | None = None, q: str | None = None,
                         sort: str = "severity", page: int = 1,
                         page_size: int = 20) -> dict:
    page = max(page, 1)
    page_size = min(max(page_size, 1), 500)
    empty = {
        "findings": [], "total": 0, "page": page, "page_size": page_size, "pages": 0,
        "summary": {"total": 0, "by_stage": {}, "by_severity": {}, "by_status": {}},
        "facets": {"categories": [], "statuses": [], "stages": _STAGES, "tasks": []},
    }
    if not db_url:
        return empty

    try:
        findings, scans, triage = await _load(db_url)
    except Exception:
        return empty

    all_rows = [_row(f, scans.get(f.scan_job_id), triage.get(f.id)) for f in findings]

    # Facets over everything (so the dropdowns are stable regardless of filters).
    tasks = {}
    for r in all_rows:
        t = r["task"]
        tasks.setdefault(t["scan_id"], {"scan_id": t["scan_id"], "domain": t["domain"]})
    facets = {
        "categories": sorted({r["category"] for r in all_rows if r["category"]}),
        "statuses": sorted({r["status"] for r in all_rows if r["status"]}),
        "stages": _STAGES,
        "tasks": list(tasks.values()),
    }

    filtered = _apply_filters(all_rows, scan_id=scan_id, severity=severity,
                              report_stage=report_stage, status=status,
                              category=category, host=host, q=q)
    filtered = _sort(filtered, sort)

    # Tiles are computed over the FILTERED set (so they track the active query).
    by_sev = Counter(r["severity"] for r in filtered)
    by_stage = Counter(r["report_stage"] for r in filtered)
    by_status = Counter(r["status"] for r in filtered if r["status"])
    summary = {
        "total": len(filtered),
        "by_severity": {s: by_sev[s] for s in _SEV_ORDER if by_sev[s]},
        "by_stage": {s: by_stage[s] for s in _STAGES if by_stage[s]},
        "by_status": dict(by_status),
    }

    total = len(filtered)
    pages = (total + page_size - 1) // page_size
    start = (page - 1) * page_size
    return {
        "findings": filtered[start:start + page_size],
        "total": total, "page": page, "page_size": page_size, "pages": pages,
        "summary": summary, "facets": facets,
    }


async def set_triage(db_url: str | None, finding_id: str, *,
                     report_stage: str | None = None, note: str | None = None,
                     verification_override: str | None = None) -> dict:
    """Upsert the operator triage row for one finding. Returns the saved state."""
    if not db_url:
        return {"ok": False, "error": "no database configured"}
    if report_stage is not None and report_stage not in _STAGES:
        return {"ok": False, "error": f"invalid report_stage: {report_stage}"}
    try:
        fid = UUID(finding_id)
    except ValueError:
        return {"ok": False, "error": "invalid finding id"}

    from sqlalchemy import select

    from database.models import Finding, FindingTriage
    from database.session import make_engine, make_session_factory

    engine = make_engine(db_url)
    try:
        await _ensure_triage(engine, db_url)
        async with make_session_factory(engine)() as s:
            # Guard: the finding must exist (a triage row for a ghost id is useless).
            exists = (await s.execute(select(Finding.id).where(Finding.id == fid))).first()
            if not exists:
                return {"ok": False, "error": "finding not found"}
            row = (await s.execute(
                select(FindingTriage).where(FindingTriage.finding_id == fid))).scalars().first()
            if row is None:
                row = FindingTriage(finding_id=fid, report_stage="pending")
                s.add(row)
            if report_stage is not None:
                row.report_stage = report_stage
            if note is not None:
                row.note = note
            if verification_override is not None:
                row.verification_override = verification_override or None
            row.updated_at = datetime.now(UTC)
            await s.commit()
            return {"ok": True, "finding_id": finding_id, "report_stage": row.report_stage,
                    "verification_override": row.verification_override, "note": row.note,
                    "updated_at": row.updated_at.isoformat()}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:200]}
    finally:
        await engine.dispose()


async def export_findings_csv(db_url: str | None, *, scan_id=None, severity=None,
                              report_stage=None, status=None, category=None,
                              host=None, q=None, sort="severity") -> str:
    """Every finding matching the filters, as CSV (no pagination)."""
    import csv
    import io

    rows: list[dict] = []
    if db_url:
        try:
            findings, scans, triage = await _load(db_url)
            all_rows = [_row(f, scans.get(f.scan_job_id), triage.get(f.id)) for f in findings]
            rows = _sort(_apply_filters(
                all_rows, scan_id=scan_id, severity=severity, report_stage=report_stage,
                status=status, category=category, host=host, q=q), sort)
        except Exception:
            rows = []
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "title", "host", "category", "status", "report_stage",
                "confidence", "task_domain", "created_at", "url"])
    for r in rows:
        w.writerow([r["severity"], r["title"], r["host"], r["category"],
                    r["status"] or "", r["report_stage"], r["confidence"] or "",
                    r["task"]["domain"], r["created_at"] or "", r["url"] or ""])
    return buf.getvalue()
