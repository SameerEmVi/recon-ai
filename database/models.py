"""
Database models (SQLModel + SQLAlchemy).

Tables:
  scan_jobs         — one row per scan run
  events            — every IN-scope event, deduped per (scan_job_id, dedup_key)
  hosts             — aggregated host view updated as events arrive
  findings          — FINDING_CANDIDATE events materialized as rows
  ai_assessments    — LLM annotations written in Phase 3 (table created now, written later)
  vocabulary        — persistent reconnaissance learning system: reusable
                      recon vocabulary (directories, files, endpoints, api paths,
                      parameters, js identifiers, …) learned from observations,
                      partitioned by knowledge scope (global / technology /
                      target / organization). Unique per (scope, category, value).
  vocabulary_targets — distinct (vocab row, target) sightings — backs target_count.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Optional

from sqlalchemy import Column, JSON, LargeBinary, UniqueConstraint
from sqlmodel import Field, SQLModel


# ── ScanJob ────────────────────────────────────────────────────────────────────

class ScanJob(SQLModel, table=True):
    __tablename__ = "scan_jobs"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    target_domain: str = Field(index=True)
    # Stored as JSON: {"in_scope": [...], "out_scope": [...], "max_distance": N}
    scope_config: Optional[Any] = Field(default=None, sa_column=Column(JSON))
    mode: str = Field(default="pentest")     # execution tier: osint | recon | pentest (legacy rows: active | vuln | full)
    #   (AI-assisted vs deterministic is orthogonal — derivable from AiAssessment rows)
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


class FindingTriage(SQLModel, table=True):
    """Operator triage state layered on top of a deterministic `Finding`.

    Kept in its own table so the recon-produced finding stays immutable — this is
    the human/bug-bounty workflow axis (report stage + note), one row per finding.
    `report_stage` tracks the submission lifecycle; `verification_override` lets an
    operator confirm/downgrade a finding's status without the engine ever promoting
    it (the deterministic-vs-human split, mirroring deterministic-vs-LLM).
    """

    __tablename__ = "finding_triage"

    finding_id: uuid.UUID = Field(foreign_key="findings.id", primary_key=True)
    # pending | submitted | accepted | rejected | duplicate | informative | triaged
    report_stage: str = Field(default="pending", index=True)
    verification_override: Optional[str] = Field(default=None)   # operator-set status
    note: Optional[str] = Field(default=None)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ── HttpExchange (evidence store — the agent-driven pentest section) ────────────

class HttpExchange(SQLModel, table=True):
    """One captured request/response pair — the *proof* a pentest finding points
    to (see docs/pentest-section-design.md §6).

    Separation of concerns, mirroring the deterministic-vs-LLM split elsewhere:
      - **URL + headers are redacted at capture** (`net.redact`): secret headers
        and sensitive query params are masked before anything touches disk, so
        they are never stored even in ciphertext.
      - **Bodies are encrypted at rest** (`evidence.crypto`) and stored verbatim
        (the proof must be exact). They decrypt only with the configured key, for
        the authorized operator — never fed to the LLM raw.
      - **Fail-closed:** with no evidence key configured, bodies are *not* stored
        (columns stay null, `bodies_dropped` says why); the redacted metadata is
        still kept, so the store degrades to today's metadata-only behaviour
        rather than writing plaintext bodies to disk.

    `finding_id` is nullable: an exchange is captured when a tool runs and is
    linked to the finding it supports once that finding exists (one finding can
    cite several exchanges; an exchange may support more than one finding via the
    strongest link — the first that claims it)."""

    __tablename__ = "http_exchanges"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    scan_job_id: uuid.UUID = Field(foreign_key="scan_jobs.id", index=True)
    finding_id: Optional[uuid.UUID] = Field(
        default=None, foreign_key="findings.id", index=True)
    host: str = Field(index=True)
    method: str
    url: str                                  # redacted (userinfo + secret params stripped)
    status_code: Optional[int] = Field(default=None)

    # Redacted header maps (secret headers masked) — safe to store as-is.
    request_headers: Optional[Any] = Field(default=None, sa_column=Column(JSON))
    response_headers: Optional[Any] = Field(default=None, sa_column=Column(JSON))

    # Bodies: Fernet ciphertext when an evidence key is configured, else null.
    request_body: Optional[bytes] = Field(default=None, sa_column=Column(LargeBinary))
    response_body: Optional[bytes] = Field(default=None, sa_column=Column(LargeBinary))
    body_encrypted: bool = Field(default=False)
    bodies_dropped: Optional[str] = Field(default=None)   # why bodies were not stored
    request_size: Optional[int] = Field(default=None)     # original plaintext byte size
    response_size: Optional[int] = Field(default=None)
    response_truncated: bool = Field(default=False)       # response body exceeded the cap

    duration_ms: Optional[float] = Field(default=None)
    source_tool: Optional[str] = Field(default=None)      # the tool/step that made the request
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ── VocabularyItem (persistent reconnaissance learning system) ──────────────────

class VocabularyItem(SQLModel, table=True):
    """One reusable reconnaissance vocabulary token, within one knowledge scope.

    A candidate is a *proposal* learned from observation — never proof that a
    resource exists. Uniqueness is DB-enforced on (scope_type, scope_key,
    category, value) so concurrent processing can never create a duplicate: the
    second inserter gets an IntegrityError and updates instead. Rarity stats and
    confidence accumulate; provenance records the first sighting.

    Knowledge scopes (scope_type / scope_key):
      global       / ""           — across all targets and technologies
      technology   / "<tech>"     — e.g. "wordpress", "iis"
      target       / "<domain>"   — the scan's seed domain
      organization / "<program>"  — an operator-supplied program/org label
    """

    __tablename__ = "vocabulary"
    __table_args__ = (
        UniqueConstraint(
            "scope_type", "scope_key", "category", "value",
            name="uq_vocab_scope_category_value",
        ),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    scope_type: str = Field(index=True)       # global | technology | target | organization
    scope_key: str = Field(default="", index=True)
    category: str = Field(index=True)         # see recon.vocabulary.CATEGORIES
    value: str = Field(index=True)            # the normalized token

    # Usefulness / rarity statistics (objective) + derived confidence.
    occurrence_count: int = Field(default=1)  # total sightings in this scope
    target_count: int = Field(default=1)      # distinct targets it was seen on
    confidence: float = Field(default=0.0, index=True)  # 0..1, recomputed on update
    context: Optional[str] = Field(default=None)        # technology/context, extensible
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Provenance of the first sighting.
    source_scan_id: Optional[uuid.UUID] = Field(default=None, index=True)
    source_event_id: Optional[uuid.UUID] = Field(default=None)
    source_url: Optional[str] = Field(default=None)     # path only, never a query string


class VocabularyTarget(SQLModel, table=True):
    """Distinct (scope, category, value, target) sightings — the source of truth
    for target_count. Unique so a repeat sighting of the same word on the same
    target under the same scope can never be double-counted, even concurrently.
    """

    __tablename__ = "vocabulary_targets"
    __table_args__ = (
        UniqueConstraint(
            "scope_type", "scope_key", "category", "value", "target",
            name="uq_vocab_target",
        ),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    scope_type: str = Field(index=True)
    scope_key: str = Field(default="", index=True)
    category: str = Field(index=True)
    value: str = Field(index=True)
    target: str = Field(index=True)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ── JobRecord (hybrid scanning engine — per-target / per-module job lifecycle) ──

class JobRecord(SQLModel, table=True):
    """Persisted lifecycle of one scheduler job (a target scan, or a module run
    against a target), so an in-progress hybrid scan can be inspected/resumed.
    Unique per (scan, dedup_key) so the same unit of work is never duplicated.
    State mirrors scheduler.jobs.JobState."""

    __tablename__ = "jobs"
    __table_args__ = (
        UniqueConstraint("scan_job_id", "dedup_key", name="uq_job_scan_dedup"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    scan_job_id: uuid.UUID = Field(foreign_key="scan_jobs.id", index=True)
    parent_job_id: Optional[uuid.UUID] = Field(default=None, index=True)
    kind: str = Field(index=True)              # "target" | "module"
    target: str = Field(index=True)
    module: Optional[str] = Field(default=None, index=True)
    state: str = Field(default="QUEUED", index=True)   # JobState.value
    priority: int = Field(default=100)
    dedup_key: str = Field(index=True)
    correlation_id: Optional[str] = Field(default=None)
    error: Optional[str] = Field(default=None)
    result: Optional[Any] = Field(default=None, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def from_job(cls, job, scan_job_id: uuid.UUID | None = None) -> "JobRecord":
        """Project a scheduler.jobs.Job onto a persistable row."""
        return cls(
            id=job.id,
            scan_job_id=scan_job_id or job.scan_id,
            parent_job_id=job.parent_id,
            kind=job.kind.value,
            target=job.target,
            module=job.module,
            state=job.state.value,
            priority=job.priority,
            dedup_key=job.dedup_key,
            correlation_id=job.correlation_id,
            error=job.error,
            result=job.result,
            created_at=job.created_at,
            updated_at=job.updated_at,
        )


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


# ── Autonomous exploration engine domain model ──────────────────────────────────
# Imported here so its tables register with SQLModel.metadata (create_all /
# init_db) alongside the core models. See database/exploration_models.py.
from database import exploration_models as _exploration_models  # noqa: E402,F401
