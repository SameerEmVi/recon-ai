"""Findings routes (token-gated).

Cross-task vulnerability overview + operator triage. Reads/writes go through
`api/findings.py`; the finding itself stays engine-owned, only the triage layer
(report stage / note / verification override) is mutable here.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from api.auth import require_token
from api.findings import build_findings, export_findings_csv, set_triage

router = APIRouter(prefix="/api", tags=["findings"], dependencies=[Depends(require_token)])


def _db(request: Request) -> str | None:
    return getattr(request.app.state.settings, "db_url", None)


@router.get("/findings")
async def findings(
    request: Request,
    scan_id: str | None = None,
    severity: str | None = None,
    report_stage: str | None = None,
    status: str | None = None,
    category: str | None = None,
    host: str | None = None,
    q: str | None = None,
    sort: str = "severity",
    page: int = 1,
    page_size: int = 20,
) -> dict:
    return await build_findings(
        _db(request), scan_id=scan_id, severity=severity, report_stage=report_stage,
        status=status, category=category, host=host, q=q, sort=sort,
        page=page, page_size=page_size,
    )


class TriageBody(BaseModel):
    report_stage: str | None = None
    note: str | None = None
    verification_override: str | None = None


@router.patch("/findings/{finding_id}/triage")
async def triage(request: Request, finding_id: str, body: TriageBody) -> dict:
    return await set_triage(
        _db(request), finding_id, report_stage=body.report_stage,
        note=body.note, verification_override=body.verification_override,
    )


@router.get("/findings/export")
async def findings_export(
    request: Request,
    scan_id: str | None = None,
    severity: str | None = None,
    report_stage: str | None = None,
    status: str | None = None,
    category: str | None = None,
    host: str | None = None,
    q: str | None = None,
    sort: str = "severity",
) -> PlainTextResponse:
    csv_text = await export_findings_csv(
        _db(request), scan_id=scan_id, severity=severity, report_stage=report_stage,
        status=status, category=category, host=host, q=q, sort=sort,
    )
    return PlainTextResponse(csv_text, media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=findings.csv"})
