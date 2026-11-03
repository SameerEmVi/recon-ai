"""Health / liveness route (unauthenticated, non-sensitive)."""

from __future__ import annotations

from fastapi import APIRouter, Request

from api.schemas import Health

router = APIRouter(tags=["health"])


@router.get("/api/health", response_model=Health)
async def health(request: Request) -> Health:
    st = request.app.state.settings
    mgr = request.app.state.scan_manager
    return Health(
        status="ok",
        version=getattr(request.app, "version", "0") or "0",
        db_configured=bool(st.db_url),      # bool only — never the URL itself
        active_scans=mgr.active_count,
    )
