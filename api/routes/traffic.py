"""Traffic routes (token-gated).

Read-only, proxy-style view over the per-run `http.jsonl` the engine writes.
Filtering and pagination happen server-side (see `api/traffic.py`). No scanning.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from api.auth import require_token
from api.traffic import build_traffic, list_runs

router = APIRouter(prefix="/api", tags=["traffic"], dependencies=[Depends(require_token)])


@router.get("/traffic/runs")
async def traffic_runs(request: Request) -> dict:
    return {"runs": list_runs(request.app.state.settings.results_dir)}


@router.get("/traffic")
async def traffic(
    request: Request,
    scan_id: str | None = None,
    run_id: str | None = None,
    domain: str | None = None,
    host: str | None = None,
    method: str | None = None,
    status: str | None = None,
    q: str | None = None,
    module: str | None = None,
    errors_only: bool = False,
    size_min: int | None = None,
    size_max: int | None = None,
    page: int = 1,
    page_size: int = 50,
) -> dict:
    return build_traffic(
        request.app.state.settings.results_dir,
        scan_id=scan_id, run_id=run_id, domain=domain,
        host=host, method=method, status=status, q=q, module=module,
        errors_only=errors_only, size_min=size_min, size_max=size_max,
        page=page, page_size=page_size,
    )
