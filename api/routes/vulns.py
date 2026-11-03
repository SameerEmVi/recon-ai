"""Vulnerability-intelligence route (token-gated).

Pure read of persisted findings (+ the vulnscan evidence JSON) for a scan. No
scan logic — feeds the Vulnerability Intelligence page.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from api.auth import require_token
from api.vulns import build_vulns

router = APIRouter(prefix="/api", tags=["vulns"], dependencies=[Depends(require_token)])


@router.get("/vulns")
async def vulns(request: Request, scan_id: str | None = None) -> dict:
    st = request.app.state.settings
    mgr = request.app.state.scan_manager
    return await build_vulns(mgr, st.db_url, scan_id)
