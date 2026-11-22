"""Plan/progress route (token-gated).

Pure read of the persisted hybrid `jobs` rows, projected into the per-target
plan/execution board. No scan logic.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from api.auth import require_token
from api.plan import build_plan

router = APIRouter(prefix="/api", tags=["plan"], dependencies=[Depends(require_token)])


@router.get("/plan")
async def plan(request: Request, scan_id: str | None = None) -> dict:
    st = request.app.state.settings
    mgr = request.app.state.scan_manager
    return await build_plan(mgr, st.db_url, scan_id)
