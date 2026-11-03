"""Dashboard overview route (token-gated)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from api.auth import require_token
from api.overview import build_overview

router = APIRouter(prefix="/api", tags=["overview"], dependencies=[Depends(require_token)])


@router.get("/overview")
async def overview(request: Request, scan_id: str | None = None) -> dict:
    st = request.app.state.settings
    mgr = request.app.state.scan_manager
    return await build_overview(mgr, st.db_url, scan_id)
