"""Report route (token-gated) — the evidence-aware vulnerability report."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse

from api.auth import require_token
from api.report import build_scan_report, render_report

router = APIRouter(prefix="/api", tags=["report"], dependencies=[Depends(require_token)])


@router.get("/report")
async def report(request: Request, scan_id: str, format: str = "md"):
    fmt = format.lower()
    if fmt not in ("text", "json", "md", "markdown"):
        raise HTTPException(status_code=400, detail="format must be text | json | md")
    db_url = getattr(request.app.state.settings, "db_url", None)
    rep, scan = await build_scan_report(db_url, scan_id, with_evidence=True)
    if rep is None:
        raise HTTPException(status_code=404, detail=f"scan {scan_id} not found")
    body = render_report(rep, fmt)
    media = "application/json" if fmt == "json" else "text/markdown" if fmt in ("md", "markdown") else "text/plain"
    return PlainTextResponse(body, media_type=media)
