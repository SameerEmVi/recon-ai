"""
Pydantic request/response schemas for the web API.

Response shapes reuse the field conventions already serialized by the MCP server
(mcpserver/server.py) so the two interfaces stay consistent.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

# The execution modes the policy layer enforces (kept in sync with policy.MODES).
Mode = Literal["osint", "vuln", "active", "full"]
ScanStatusValue = Literal["running", "complete", "failed", "cancelled", "not_found", "unknown"]


class ScanCreate(BaseModel):
    """A scan request. The backend re-validates scope before anything runs."""
    domain: str = Field(..., min_length=1, description="Root/seed domain to scan.")
    in_scope: list[str] | None = Field(None, description="Scope rules; default [*.domain, domain].")
    out_scope: list[str] = Field(default_factory=list, description="Deny rules (deny wins).")
    max_distance: int = Field(5, ge=0, le=10)
    wildcard_apex: bool = False
    mode: Mode = "active"
    modules: list[str] | None = Field(None, description="Explicit module list; else mode defaults.")
    # Rate / concurrency (None = unlimited; adaptive WAF backoff still applies).
    rate_limit: float | None = Field(None, gt=0)
    max_concurrency: int | None = Field(None, gt=0)
    module_concurrency: int | None = Field(None, gt=0, description="Max simultaneous requests per host.")
    # Hybrid parallel engine (opt-in).
    hybrid: bool = False
    workers: int = Field(10, ge=1, le=50)
    targets: list[str] | None = Field(None, description="Authorized subdomains for --hybrid.")
    # Misc
    browser_profile: str = "chrome-windows"
    proxy: str | None = None


class ScanCreated(BaseModel):
    scan_id: str
    domain: str
    status: ScanStatusValue
    mode: str


class ScanStatus(BaseModel):
    scan_id: str
    domain: str
    status: ScanStatusValue
    mode: str | None = None
    event_count: int = 0
    error: str | None = None
    created_at: datetime | None = None
    completed_at: datetime | None = None


class Health(BaseModel):
    status: Literal["ok"]
    version: str
    db_configured: bool
    active_scans: int


class Message(BaseModel):
    detail: str


# Generic row passthroughs (hosts/findings) — the engine already sanitizes these.
class GenericRows(BaseModel):
    items: list[dict[str, Any]]
