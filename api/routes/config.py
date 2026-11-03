"""Read-only configuration route (token-gated).

Reports effective non-sensitive settings + engine defaults for the Settings
page. Never returns the token, the DB URL, or any credential.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from api.auth import require_token
from api.sysinfo import build_config

router = APIRouter(prefix="/api", tags=["config"], dependencies=[Depends(require_token)])


@router.get("/config")
async def config(request: Request) -> dict:
    st = request.app.state.settings
    version = getattr(request.app, "version", "0") or "0"
    return build_config(st, version)
