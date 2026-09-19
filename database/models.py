"""
Database models (SQLModel + SQLAlchemy).

Tables:
  scan_jobs       — one row per scan run
  events          — every IN-scope event, deduped per (scan_job_id, dedup_key)
  hosts           — aggregated host view updated as events arrive
  findings        — FINDING_CANDIDATE events materialized as rows
  ai_assessments  — LLM annotations written in Phase 3 (table created now, written later)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Optional

from sqlalchemy import Column, JSON, UniqueConstraint
from sqlmodel import Field, SQLModel


# ── ScanJob ────────────────────────────────────────────────────────────────────

class ScanJob(SQLModel, table=True):
    __tablename__ = "scan_jobs"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    target_domain: str = Field(index=True)
    # Stored as JSON: {"in_scope": [...], "out_scope": [...], "max_distance": N}
    scope_config: Optional[Any] = Field(default=None, sa_column=Column(JSON))
    mode: str = Field(default="A")           # "A" = deterministic, "B" = AI-assisted
    status: str = Field(default="running")   # running / complete / failed
    event_count: int = Field(default=0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: Optional[datetime] = Field(default=None)


# ── EventRecord ────────────────────────────────────────────────────────────────

class EventRecord(SQLModel, table=True):
    __tablename__ = "events"
    __table_args__ = (
        UniqueConstraint("scan_job_id", "dedup_key", name="uq_event_scan_dedup"),
    )

    id: uuid.UUID = Field(primary_key=True)
    scan_job_id: uuid.UUID = Field(
        foreign_key="scan_jobs.id", index=True
    )
    type: str = Field(index=True)            # EventType.value
    data: Optional[Any] = Field(default=None, sa_column=Column(JSON))
    scope_status: str                        # ScopeStatus.value
    distance: int
    dedup_key: str = Field(index=True)
    source_tool: str
    source_event_id: Optional[uuid.UUID] = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def from_event(cls, event: "Event") -> "EventRecord":  # type: ignore[name-defined]
        return cls(
            id=event.id,
            scan_job_id=event.scan_job_id,
            type=event.type.value,
            data=event.data.model_dump(),
            scope_status=event.scope_status.value,
            distance=event.distance,
            dedup_key=event.dedup_key,
            source_tool=event.source_tool,
            source_event_id=event.source_event_id,
            created_at=event.created_at,
        )


# ── Host ───────────────────────────────────────────────────────────────────────

class Host(SQLModel, table=True):
    __tablename__ = "hosts"
    __table_args__ = (
        UniqueConstraint("scan_job_id", "hostname", name="uq_host_scan_hostname"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    scan_job_id: uuid.UUID = Field(foreign_key="scan_jobs.id", index=True)
    hostname: str = Field(index=True)
    # Aggregated lists — updated incrementally as events arrive
    ip_addresses: Optional[Any] = Field(default=None, sa_column=Column(JSON))  # list[str]
    open_ports: Optional[Any] = Field(default=None, sa_column=Column(JSON))    # list[int]
    technologies: Optional[Any] = Field(default=None, sa_column=Column(JSON))  # list[str]
    services: Optional[Any] = Field(default=None, sa_column=Column(JSON))      # list[{url,status_code,title}]
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ── Finding ────────────────────────────────────────────────────────────────────

class Finding(SQLModel, table=True):
    __tablename__ = "findings"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    scan_job_id: uuid.UUID = Field(foreign_key="scan_jobs.id", index=True)
    host: str = Field(index=True)
    title: str
    description: str
    category: str = Field(index=True)
    severity_hint: Optional[str] = Field(default=None)
    evidence: Optional[Any] = Field(default=None, sa_column=Column(JSON))
    source_event_id: Optional[uuid.UUID] = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ── AiAssessment (Phase 3 stub) ────────────────────────────────────────────────

class AiAssessment(SQLModel, table=True):
    __tablename__ = "ai_assessments"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    scan_job_id: uuid.UUID = Field(foreign_key="scan_jobs.id", index=True)
    target_type: str           # "host" | "finding" | "endpoint"
    target_id: uuid.UUID = Field(index=True)
    importance: Optional[str] = Field(default=None)          # low / medium / high / critical
    environment_guess: Optional[str] = Field(default=None)   # prod / staging / dev / internal
    attack_surface_notes: Optional[str] = Field(default=None)
    assessment: Optional[Any] = Field(default=None, sa_column=Column(JSON))
    model_used: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
