"""
Recon-AI MCP server.

Exposes the recon platform as MCP tools so any MCP-compatible client
(Claude Desktop, etc.) can drive scans, query results, and read assessments
without touching the CLI directly.

Run:
    python -m mcpserver.server          # stdio transport (default)
    recon-ai-mcp                        # if installed as entry point

Claude Desktop config (~/.claude/claude_desktop_config.json):
    {
      "mcpServers": {
        "recon-ai": {
          "command": "recon-ai-mcp",
          "env": {
            "RECON_AI_DB_URL": "postgresql+asyncpg://user:pass@localhost/recon_ai",
            "ANTHROPIC_API_KEY": "sk-ant-..."
          }
        }
      }
    }

Tools
-----
start_scan          — kick off a scan in the background; returns scan_id
get_scan_status     — check running / complete / failed
list_scans          — recent scans for a domain
list_hosts          — all hosts discovered in a scan
list_findings       — all FINDING_CANDIDATE events in a scan
list_assessments    — AI triage assessments for hosts / findings
compute_diff        — what changed between two scans
run_triage          — post-hoc LLM triage on a completed scan
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any
from uuid import UUID

from mcp.server.fastmcp import FastMCP

from mcpserver.context import (
    complete_scan,
    fail_scan,
    get_api_key,
    get_db_url,
    get_scan_entry,
    register_scan,
)

log = logging.getLogger(__name__)

mcp = FastMCP(
    "recon-ai",
    instructions=(
        "Recon-AI is an AI-assisted bug bounty reconnaissance platform. "
        "Use start_scan to enumerate a domain, then list_hosts and list_findings "
        "to read structured results. All targets must be authorized. "
        "Never scan domains without explicit written permission."
    ),
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _resolve_db_url(db_url: str | None) -> str:
    effective = db_url or get_db_url()
    if not effective:
        raise ValueError(
            "No database URL. Pass db_url parameter or set RECON_AI_DB_URL env var."
        )
    return effective


def _serialize_host(host: Any) -> dict:
    return {
        "id": str(host.id),
        "hostname": host.hostname,
        "ip_addresses": host.ip_addresses or [],
        "open_ports": host.open_ports or [],
        "technologies": host.technologies or [],
        "services": host.services or [],
        "first_seen": host.first_seen.isoformat() if host.first_seen else None,
    }


def _serialize_finding(f: Any) -> dict:
    return {
        "id": str(f.id),
        "host": f.host,
        "title": f.title,
        "description": f.description,
        "category": f.category,
        "severity_hint": f.severity_hint,
        "evidence": f.evidence or {},
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


def _serialize_assessment(a: Any) -> dict:
    return {
        "id": str(a.id),
        "target_type": a.target_type,
        "target_id": str(a.target_id),
        "importance": a.importance,
        "environment": a.environment_guess,
        "attack_surface_notes": a.attack_surface_notes,
        "assessment": a.assessment or {},
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


async def _run_scan_bg(
    scan_id: str,
    domain: str,
    in_scope: list[str],
    out_scope: list[str],
    max_distance: int,
    wildcard_apex: bool,
    ai: bool,
    agent: bool,
    max_iterations: int,
    db_url: str,
    api_key: str | None,
    ai_model: str,
    rate_limit: float | None,
    max_concurrency: int | None,
) -> None:
    """Background task that runs the full scan lifecycle."""
    from controller.controller import ScanController
    from scope.types import Scope

    try:
        scope = Scope.from_strings(
            in_scope=in_scope,
            out_scope=out_scope,
            max_distance=max_distance,
            wildcard_includes_apex=wildcard_apex,
        )
        controller = ScanController(
            scope,
            ai_enabled=ai,
            agent_enabled=agent,
            db_url=db_url,
            anthropic_api_key=api_key,
            ai_model=ai_model,
            max_agent_iterations=max_iterations,
            rate_limit=rate_limit,
            max_concurrency=max_concurrency,
        )
        await controller.run(domain)
        complete_scan(scan_id, controller.bus.seen_count)
    except Exception as exc:
        log.error("[mcp] scan %s failed: %s", scan_id, exc)
        fail_scan(scan_id, str(exc))


# ── tools ─────────────────────────────────────────────────────────────────────

@mcp.tool()
async def start_scan(
    domain: str,
    db_url: str | None = None,
    in_scope: list[str] | None = None,
    out_scope: list[str] | None = None,
    max_distance: int = 5,
    wildcard_apex: bool = False,
    ai: bool = False,
    agent: bool = False,
    max_iterations: int = 20,
    ai_model: str = "claude-sonnet-4-6",
    rate_limit: float | None = None,
    max_concurrency: int | None = None,
) -> dict:
    """
    Start a reconnaissance scan against an authorized domain.

    The scan runs in the background. Use get_scan_status(scan_id) to poll
    progress and list_hosts / list_findings once it completes.

    Parameters
    ----------
    domain          Root domain to enumerate (e.g. "example.com").
    db_url          Override the RECON_AI_DB_URL env var. Required if not set.
    in_scope        Scope rules. Defaults to ["*.domain", "domain"].
    out_scope       Out-of-scope rules. Deny wins over any allow.
    max_distance    Max subdomain distance from seed (default 5).
    wildcard_apex   Let *.example.com also match example.com.
    ai              Enable LLM triage after enumeration (Phase 3).
    agent           Enable constrained agent loop after triage (Phase 4).
    max_iterations  Agent iteration cap (default 20).
    ai_model        Anthropic model. Default: claude-sonnet-4-6.
    rate_limit      Max requests/sec per bucket. None = unlimited (adaptive WAF
                    backoff still applies if the target starts blocking).
    max_concurrency Max simultaneous recon operations. None = unlimited.

    IMPORTANT: Only scan domains you are explicitly authorized to test.
    """
    effective_db_url = _resolve_db_url(db_url)
    resolved_in = list(in_scope) if in_scope else [f"*.{domain}", domain]
    resolved_out = list(out_scope) if out_scope else []
    ai_effective = ai or agent
    api_key = get_api_key() if ai_effective else None

    # Create a placeholder ScanController just to get the scan_id,
    # then launch the real scan as a background task.
    import uuid as _uuid
    scan_id = str(_uuid.uuid4())
    register_scan(scan_id, domain)

    asyncio.create_task(
        _run_scan_bg(
            scan_id=scan_id,
            domain=domain,
            in_scope=resolved_in,
            out_scope=resolved_out,
            max_distance=max_distance,
            wildcard_apex=wildcard_apex,
            ai=ai_effective,
            agent=agent,
            max_iterations=max_iterations,
            db_url=effective_db_url,
            api_key=api_key,
            ai_model=ai_model,
            rate_limit=rate_limit,
            max_concurrency=max_concurrency,
        )
    )

    return {
        "scan_id": scan_id,
        "domain": domain,
        "status": "running",
        "message": (
            f"Scan started for {domain}. "
            f"Poll get_scan_status('{scan_id}') to check progress."
        ),
    }


@mcp.tool()
async def get_scan_status(scan_id: str, db_url: str | None = None) -> dict:
    """
    Check the status of a running or completed scan.

    Returns status ("running" | "complete" | "failed"), event count,
    and error message if failed. Also reads the DB record if available.
    """
    # Check in-process registry first (fast path for running scans).
    entry = get_scan_entry(scan_id)
    if entry:
        result: dict = {
            "scan_id": scan_id,
            "domain": entry.domain,
            "status": entry.status,
            "event_count": entry.event_count,
        }
        if entry.error:
            result["error"] = entry.error
        return result

    # Fall back to DB if the server restarted since the scan ran.
    try:
        effective_db_url = _resolve_db_url(db_url)
        from database.repository import ScanRepository
        from database.session import make_engine, make_session_factory
        engine = make_engine(effective_db_url)
        async with make_session_factory(engine)() as session:
            scan = await ScanRepository(session).get(UUID(scan_id))
        if scan is None:
            return {"scan_id": scan_id, "status": "not_found"}
        return {
            "scan_id": str(scan.id),
            "domain": scan.target_domain,
            "status": scan.status,
            "mode": scan.mode,
            "event_count": scan.event_count,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        }
    except Exception as exc:
        return {"scan_id": scan_id, "status": "unknown", "error": str(exc)}


@mcp.tool()
async def list_scans(
    domain: str,
    db_url: str | None = None,
    limit: int = 10,
) -> list[dict]:
    """List recent scans for a domain, newest first."""
    effective_db_url = _resolve_db_url(db_url)
    from database.repository import ScanRepository
    from database.session import make_engine, make_session_factory
    engine = make_engine(effective_db_url)
    async with make_session_factory(engine)() as session:
        scans = await ScanRepository(session).recent(domain, limit=limit)
    return [
        {
            "scan_id": str(s.id),
            "status": s.status,
            "mode": s.mode,
            "event_count": s.event_count,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in scans
    ]


@mcp.tool()
async def list_hosts(scan_id: str, db_url: str | None = None) -> list[dict]:
    """
    List all hosts discovered in a scan, with IPs, ports, technologies, and services.
    """
    effective_db_url = _resolve_db_url(db_url)
    from database.repository import HostRepository
    from database.session import make_engine, make_session_factory
    engine = make_engine(effective_db_url)
    async with make_session_factory(engine)() as session:
        hosts = await HostRepository(session).list_for_scan(UUID(scan_id))
    return [_serialize_host(h) for h in hosts]


@mcp.tool()
async def list_findings(scan_id: str, db_url: str | None = None) -> list[dict]:
    """List all finding candidates from a scan, ordered by severity."""
    effective_db_url = _resolve_db_url(db_url)
    from database.repository import FindingRepository
    from database.session import make_engine, make_session_factory
    engine = make_engine(effective_db_url)
    async with make_session_factory(engine)() as session:
        findings = await FindingRepository(session).list_for_scan(UUID(scan_id))
    return [_serialize_finding(f) for f in findings]


@mcp.tool()
async def list_assessments(
    scan_id: str,
    db_url: str | None = None,
    target_type: str | None = None,
) -> list[dict]:
    """
    List AI triage assessments for a scan.

    target_type filters to "host" or "finding" assessments only.
    Returns importance, environment, attack surface notes.
    """
    effective_db_url = _resolve_db_url(db_url)
    from database.repository import AiAssessmentRepository
    from database.session import make_engine, make_session_factory
    engine = make_engine(effective_db_url)
    async with make_session_factory(engine)() as session:
        assessments = await AiAssessmentRepository(session).list_for_scan(
            UUID(scan_id), target_type=target_type
        )
    return [_serialize_assessment(a) for a in assessments]


@mcp.tool()
async def compute_diff(
    scan_a: str,
    scan_b: str,
    db_url: str | None = None,
) -> str:
    """
    Compare two scans and return a human-readable diff.

    scan_a is the baseline; scan_b is the newer scan.
    Returns new subdomains/ports/services discovered and any that disappeared.
    """
    effective_db_url = _resolve_db_url(db_url)
    from database.diff import compute_diff as _compute_diff
    from database.repository import EventRepository
    from database.session import make_engine, make_session_factory
    engine = make_engine(effective_db_url)
    async with make_session_factory(engine)() as session:
        result = await _compute_diff(
            EventRepository(session), UUID(scan_a), UUID(scan_b)
        )
    return result.summary()


@mcp.tool()
async def run_triage(
    scan_id: str,
    db_url: str | None = None,
    ai_model: str = "claude-sonnet-4-6",
) -> str:
    """
    Run LLM triage on a completed scan (post-hoc).

    Reads structured host and finding records from the DB, calls the LLM
    to annotate importance/environment/attack surface, and returns a
    formatted summary. Requires ANTHROPIC_API_KEY env var.
    """
    effective_db_url = _resolve_db_url(db_url)
    api_key = get_api_key()
    if not api_key:
        return "Error: ANTHROPIC_API_KEY env var not set."

    from ai.triage import Triage
    from database.repository import (
        AiAssessmentRepository,
        FindingRepository,
        HostRepository,
        ScanRepository,
    )
    from database.session import make_engine, make_session_factory

    engine = make_engine(effective_db_url)
    async with make_session_factory(engine)() as session:
        scan = await ScanRepository(session).get(UUID(scan_id))
        if scan is None:
            return f"Error: scan {scan_id} not found."
        triage = Triage(
            api_key=api_key,
            host_repo=HostRepository(session),
            finding_repo=FindingRepository(session),
            assessment_repo=AiAssessmentRepository(session),
            model=ai_model,
        )
        report = await triage.assess_scan(UUID(scan_id), scan.target_domain)
    return report.print_summary()


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)-8s %(name)s  %(message)s")
    mcp.run()


if __name__ == "__main__":
    main()
