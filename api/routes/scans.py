"""Scan lifecycle routes: create / list / status / cancel (all token-gated).

Handlers validate input and delegate to the ScanManager — they never run modules
directly. Scope is re-checked inside ScanManager.launch (backend-authoritative).
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status

from api.auth import require_token
from api.scans import ScopeRejected
from api.schemas import ScanCreate, ScanCreated, ScanStatus

router = APIRouter(prefix="/api/scans", tags=["scans"], dependencies=[Depends(require_token)])


def _mgr(request: Request):
    return request.app.state.scan_manager


@router.post("", response_model=ScanCreated, status_code=status.HTTP_201_CREATED)
async def create_scan(request: Request, cfg: ScanCreate) -> ScanCreated:
    try:
        entry = await _mgr(request).launch(cfg)
    except ScopeRejected as exc:
        # Out-of-scope / invalid scope is a client error, not a server fault.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return ScanCreated(scan_id=entry.scan_id, domain=entry.domain,
                       status="running", mode=entry.mode)


@router.get("", response_model=list[ScanStatus])
async def list_scans(request: Request) -> list[ScanStatus]:
    return [
        ScanStatus(scan_id=e.scan_id, domain=e.domain, status=e.status, mode=e.mode,
                   event_count=e.event_count, error=e.error,
                   created_at=e.created_at, completed_at=e.completed_at)
        for e in _mgr(request).list()
    ]


@router.get("/{scan_id}", response_model=ScanStatus)
async def scan_status(request: Request, scan_id: str) -> ScanStatus:
    entry = _mgr(request).get(scan_id)
    if entry is not None:
        return ScanStatus(scan_id=entry.scan_id, domain=entry.domain, status=entry.status,
                          mode=entry.mode, event_count=entry.event_count, error=entry.error,
                          created_at=entry.created_at, completed_at=entry.completed_at)
    # Fall back to the DB (server restarted since the scan ran).
    db_url = request.app.state.settings.db_url
    if db_url:
        try:
            from database.repository import ScanRepository
            from database.session import make_engine, make_session_factory
            engine = make_engine(db_url)
            try:
                async with make_session_factory(engine)() as session:
                    scan = await ScanRepository(session).get(UUID(scan_id))
            finally:
                await engine.dispose()
            if scan is not None:
                return ScanStatus(scan_id=str(scan.id), domain=scan.target_domain,
                                  status=scan.status, mode=scan.mode,
                                  event_count=scan.event_count,
                                  created_at=scan.created_at, completed_at=scan.completed_at)
        except Exception:
            pass
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")


@router.post("/{scan_id}/cancel", response_model=ScanStatus)
async def cancel_scan(request: Request, scan_id: str) -> ScanStatus:
    mgr = _mgr(request)
    ok = await mgr.cancel(scan_id)
    entry = mgr.get(scan_id)
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    if not ok and entry.status == "running":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="could not cancel")
    return ScanStatus(scan_id=entry.scan_id, domain=entry.domain, status=entry.status,
                      mode=entry.mode, event_count=entry.event_count, error=entry.error,
                      created_at=entry.created_at, completed_at=entry.completed_at)
