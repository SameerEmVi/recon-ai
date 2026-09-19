"""
Repository layer — thin typed wrappers around AsyncSession.

Each repository owns one or two related tables and exposes
intent-revealing methods. No business logic lives here.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import AiAssessment, EventRecord, Finding, Host, ScanJob
from events.types import EventType

if TYPE_CHECKING:
    from events.types import Event


# ── AiAssessmentRepository ─────────────────────────────────────────────────────

class AiAssessmentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def save(self, assessment: AiAssessment) -> AiAssessment:
        self._s.add(assessment)
        await self._s.commit()
        await self._s.refresh(assessment)
        return assessment

    async def list_for_scan(
        self, scan_id: UUID, target_type: str | None = None
    ) -> list[AiAssessment]:
        q = select(AiAssessment).where(AiAssessment.scan_job_id == scan_id)
        if target_type:
            q = q.where(AiAssessment.target_type == target_type)
        result = await self._s.execute(q.order_by(AiAssessment.created_at))
        return list(result.scalars())

    async def get_for_target(self, target_id: UUID) -> AiAssessment | None:
        result = await self._s.execute(
            select(AiAssessment).where(AiAssessment.target_id == target_id)
        )
        return result.scalar_one_or_none()


# ── ScanRepository ─────────────────────────────────────────────────────────────

class ScanRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def create(
        self,
        scan_id: UUID,
        domain: str,
        scope_config: dict,
        mode: str,
    ) -> ScanJob:
        job = ScanJob(
            id=scan_id,
            target_domain=domain,
            scope_config=scope_config,
            mode=mode,
        )
        self._s.add(job)
        await self._s.commit()
        await self._s.refresh(job)
        return job

    async def complete(self, scan_id: UUID, event_count: int) -> None:
        await self._s.execute(
            update(ScanJob)
            .where(ScanJob.id == scan_id)
            .values(status="complete", completed_at=datetime.now(UTC), event_count=event_count)
        )
        await self._s.commit()

    async def fail(self, scan_id: UUID) -> None:
        await self._s.execute(
            update(ScanJob).where(ScanJob.id == scan_id).values(status="failed")
        )
        await self._s.commit()

    async def get(self, scan_id: UUID) -> ScanJob | None:
        result = await self._s.execute(select(ScanJob).where(ScanJob.id == scan_id))
        return result.scalar_one_or_none()

    async def recent(self, domain: str, limit: int = 10) -> list[ScanJob]:
        result = await self._s.execute(
            select(ScanJob)
            .where(ScanJob.target_domain == domain)
            .order_by(ScanJob.created_at.desc())
            .limit(limit)
        )
        return list(result.scalars())


# ── EventRepository ────────────────────────────────────────────────────────────

class EventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def save(self, event: "Event") -> bool:
        """Persist an event. Returns False if a duplicate dedup_key exists for this scan."""
        record = EventRecord.from_event(event)
        try:
            self._s.add(record)
            await self._s.commit()
            return True
        except IntegrityError:
            await self._s.rollback()
            return False

    async def get_by_type(
        self, scan_id: UUID, event_type: EventType
    ) -> list[EventRecord]:
        result = await self._s.execute(
            select(EventRecord).where(
                EventRecord.scan_job_id == scan_id,
                EventRecord.type == event_type.value,
            )
        )
        return list(result.scalars())

    async def dedup_keys(self, scan_id: UUID, event_type: EventType) -> set[str]:
        """Return the set of dedup_keys for a given (scan, event_type) pair.
        Used by compute_diff() for O(n) set comparison."""
        result = await self._s.execute(
            select(EventRecord.dedup_key).where(
                EventRecord.scan_job_id == scan_id,
                EventRecord.type == event_type.value,
            )
        )
        return {row[0] for row in result}

    async def count(self, scan_id: UUID) -> int:
        from sqlalchemy import func
        result = await self._s.execute(
            select(func.count()).select_from(EventRecord).where(
                EventRecord.scan_job_id == scan_id
            )
        )
        return result.scalar_one()


# ── HostRepository ─────────────────────────────────────────────────────────────

class HostRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def ensure(self, scan_id: UUID, hostname: str) -> Host:
        """Return existing host or create it."""
        result = await self._s.execute(
            select(Host).where(Host.scan_job_id == scan_id, Host.hostname == hostname)
        )
        host = result.scalar_one_or_none()
        if host is None:
            host = Host(
                scan_job_id=scan_id,
                hostname=hostname,
                ip_addresses=[],
                open_ports=[],
                technologies=[],
                services=[],
            )
            self._s.add(host)
            await self._s.commit()
            await self._s.refresh(host)
        return host

    async def add_ip(self, scan_id: UUID, hostname: str, ip: str) -> None:
        host = await self.ensure(scan_id, hostname)
        ips: list = host.ip_addresses or []
        if ip not in ips:
            ips.append(ip)
            await self._s.execute(
                update(Host).where(Host.id == host.id).values(ip_addresses=ips)
            )
            await self._s.commit()

    async def add_port(self, scan_id: UUID, hostname: str, port: int) -> None:
        host = await self.ensure(scan_id, hostname)
        ports: list = host.open_ports or []
        if port not in ports:
            ports.append(port)
            await self._s.execute(
                update(Host).where(Host.id == host.id).values(open_ports=sorted(ports))
            )
            await self._s.commit()

    async def add_technology(self, scan_id: UUID, hostname: str, tech: str) -> None:
        host = await self.ensure(scan_id, hostname)
        techs: list = host.technologies or []
        if tech not in techs:
            techs.append(tech)
            await self._s.execute(
                update(Host).where(Host.id == host.id).values(technologies=techs)
            )
            await self._s.commit()

    async def add_service(
        self, scan_id: UUID, hostname: str, service: dict
    ) -> None:
        host = await self.ensure(scan_id, hostname)
        services: list = host.services or []
        url = service.get("url", "")
        if not any(s.get("url") == url for s in services):
            services.append(service)
            await self._s.execute(
                update(Host).where(Host.id == host.id).values(services=services)
            )
            await self._s.commit()

    async def list_for_scan(self, scan_id: UUID) -> list[Host]:
        result = await self._s.execute(
            select(Host).where(Host.scan_job_id == scan_id).order_by(Host.hostname)
        )
        return list(result.scalars())


# ── FindingRepository ──────────────────────────────────────────────────────────

class FindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def save(self, finding: Finding) -> Finding:
        self._s.add(finding)
        await self._s.commit()
        await self._s.refresh(finding)
        return finding

    async def from_event(self, event: "Event") -> Finding | None:
        """Create a Finding row from a FINDING_CANDIDATE event."""
        from events.types import EventType, FindingCandidateData
        if event.type is not EventType.FINDING_CANDIDATE:
            return None
        d: FindingCandidateData = event.data  # type: ignore[assignment]
        finding = Finding(
            scan_job_id=event.scan_job_id,
            host=d.host,
            title=d.title,
            description=d.description,
            category=d.category,
            severity_hint=d.severity_hint,
            evidence=d.evidence,
            source_event_id=event.id,
        )
        return await self.save(finding)

    async def list_for_scan(self, scan_id: UUID) -> list[Finding]:
        result = await self._s.execute(
            select(Finding)
            .where(Finding.scan_job_id == scan_id)
            .order_by(Finding.category, Finding.host)
        )
        return list(result.scalars())
