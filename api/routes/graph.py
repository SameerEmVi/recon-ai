"""Asset-graph route (token-gated).

Pure read of the persisted event stream, projected into the entity graph that
feeds the live Map view. No scan logic.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from api.auth import require_token
from api.graph import build_graph

router = APIRouter(prefix="/api", tags=["graph"], dependencies=[Depends(require_token)])


@router.get("/graph")
async def graph(request: Request, scan_id: str | None = None) -> dict:
    st = request.app.state.settings
    mgr = request.app.state.scan_manager
    return await build_graph(mgr, st.db_url, scan_id)
