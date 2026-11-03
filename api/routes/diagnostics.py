"""Diagnostics routes (token-gated).

Read-only surface over the per-run JSONL the engine writes, plus a standalone
proxy-connectivity probe. No scanning is performed.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from api.auth import require_token
from api.diagnostics import list_runs, proxy_check, read_run

router = APIRouter(prefix="/api", tags=["diagnostics"], dependencies=[Depends(require_token)])


@router.get("/diagnostics/runs")
async def diagnostics_runs(request: Request) -> dict:
    return {"runs": list_runs(request.app.state.settings.results_dir)}


@router.get("/diagnostics")
async def diagnostics(request: Request, domain: str | None = None, run_id: str | None = None,
                      stream: str = "events", module: str | None = None,
                      limit: int = 100) -> dict:
    results_dir = request.app.state.settings.results_dir
    return read_run(results_dir, domain=domain, run_id=run_id, stream=stream,
                    module=module, limit=min(max(limit, 1), 500))


class ProxyCheckBody(BaseModel):
    url: str


@router.post("/diagnostics/proxy-check")
async def diagnostics_proxy_check(body: ProxyCheckBody) -> dict:
    return await proxy_check(body.url)
