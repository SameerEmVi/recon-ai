"""Tool-execution mindmap route (token-gated). Read-only projection of a scan."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from api.auth import require_token
from api.execmap import build_execmap

router = APIRouter(prefix="/api", tags=["execmap"], dependencies=[Depends(require_token)])


@router.get("/execmap")
async def execmap(request: Request, scan_id: str | None = None) -> dict:
    st = request.app.state.settings
    mgr = request.app.state.scan_manager
    return await build_execmap(mgr, st.db_url, scan_id)
