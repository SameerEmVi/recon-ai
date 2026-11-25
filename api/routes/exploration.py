"""Exploration-graph route (token-gated). Read-only reasoning projection of a scan."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from api.auth import require_token
from api.exploration import build_exploration

router = APIRouter(prefix="/api", tags=["exploration"], dependencies=[Depends(require_token)])


@router.get("/exploration")
async def exploration(request: Request, scan_id: str | None = None) -> dict:
    st = request.app.state.settings
    mgr = request.app.state.scan_manager
    return await build_exploration(mgr, st.db_url, scan_id)
