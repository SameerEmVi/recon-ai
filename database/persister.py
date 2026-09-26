"""
Persister — optional DB-persistence plugin for ScanController.

Injected into ScanController when --db-url is given. If absent, the scan runs
without persistence (in-memory only). The scan logic is identical either way.
"""

from __future__ import annotations

import asyncio
import logging
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from database.models import Finding
from database.repository import AiAssessmentRepository, EventRepository, FindingRepository, HostRepository, ScanRepository
from events.types import Event, EventType

log = logging.getLogger(__name__)


class Persister:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._scan_repo = ScanRepository(session)
        self._event_repo = EventRepository(session)
        self._host_repo = HostRepository(session)
        self._finding_repo = FindingRepository(session)
        self._assessment_repo = AiAssessmentRepository(session)
        # A single AsyncSession is NOT safe for concurrent use. The controller
        # fires save_event() as many parallel background tasks, so every write
        # must be serialized through this lock — otherwise overlapping commit()/
        # flush calls raise IllegalStateChangeError and corrupt the session.
        self._lock = asyncio.Lock()

    async def scan_start(
        self, scan_id: UUID, domain: str, scope_config: dict, mode: str
    ) -> None:
        async with self._lock:
            await self._scan_repo.create(scan_id, domain, scope_config, mode)
        log.debug("db: scan_start %s", scan_id)

    async def save_event(self, event: Event) -> None:
        """Persist an event and update derived tables (Host, Finding).

        Serialized via self._lock (shared session) and rolled back on error so a
        single failed write can never poison the session for subsequent events.
        """
        async with self._lock:
            try:
                saved = await self._event_repo.save(event)
                if not saved:
                    return  # duplicate — already handled by bus dedup, but be safe

                await self._update_host(event)

                if event.type is EventType.FINDING_CANDIDATE:
                    await self._finding_repo.from_event(event)
            except Exception as exc:
                log.debug("db: save_event failed (%s) — rolling back", exc)
                await self._session.rollback()

    async def scan_end(self, scan_id: UUID, event_count: int) -> None:
        async with self._lock:
            await self._scan_repo.complete(scan_id, event_count)
        log.debug("db: scan_end %s  events=%d", scan_id, event_count)

    async def scan_fail(self, scan_id: UUID) -> None:
        async with self._lock:
            await self._scan_repo.fail(scan_id)

    # ── host table maintenance ─────────────────────────────────────────────────

    async def _update_host(self, event: Event) -> None:
        """Route event data into the hosts table."""
        match event.type:
            case EventType.SUBDOMAIN:
                await self._host_repo.ensure(event.scan_job_id, event.data.hostname)

            case EventType.IP:
                if event.data.resolved_from:
                    await self._host_repo.add_ip(
                        event.scan_job_id, event.data.resolved_from, event.data.address
                    )

            case EventType.OPEN_PORT:
                await self._host_repo.add_port(
                    event.scan_job_id, event.data.host, event.data.port
                )

            case EventType.HTTP_SERVICE:
                hostname = self._url_hostname(event.data.url) or event.data.url
                await self._host_repo.add_service(
                    event.scan_job_id,
                    hostname,
                    {
                        "url": event.data.url,
                        "status_code": event.data.status_code,
                        "title": event.data.title,
                        "server": event.data.server,
                    },
                )

            case EventType.TECHNOLOGY:
                label = event.data.name
                if event.data.version:
                    label = f"{label}/{event.data.version}"
                await self._host_repo.add_technology(
                    event.scan_job_id, event.data.host, label
                )

    @staticmethod
    def _url_hostname(url: str) -> str:
        import urllib.parse
        try:
            return urllib.parse.urlparse(url).hostname or ""
        except Exception:
            return ""
