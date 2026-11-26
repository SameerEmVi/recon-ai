"""Evidence routes (token-gated) — captured request/response proof (read-only)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from api.auth import require_token
from api.evidence import build_evidence, evidence_summary

router = APIRouter(prefix="/api", tags=["evidence"], dependencies=[Depends(require_token)])


def _db(request: Request) -> str | None:
    return getattr(request.app.state.settings, "db_url", None)


@router.get("/evidence")
async def evidence(
    request: Request,
    scan_id: str | None = None,
    finding_id: str | None = None,
    limit: int = 500,
) -> dict:
    return await build_evidence(_db(request), scan_id=scan_id,
                                finding_id=finding_id, limit=limit)


@router.get("/evidence/summary")
async def summary(request: Request, scan_id: str | None = None) -> dict:
    return await evidence_summary(_db(request), scan_id=scan_id)
