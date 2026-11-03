"""Asset inventory route (token-gated).

Pure read of the aggregated `hosts` table + persisted DNS/subdomain events for a
scan. No scan logic — feeds the Asset Explorer page.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from api.auth import require_token
from api.assets import build_assets

router = APIRouter(prefix="/api", tags=["assets"], dependencies=[Depends(require_token)])


@router.get("/assets")
async def assets(request: Request, scan_id: str | None = None) -> dict:
    st = request.app.state.settings
    mgr = request.app.state.scan_manager
    return await build_assets(mgr, st.db_url, scan_id)
